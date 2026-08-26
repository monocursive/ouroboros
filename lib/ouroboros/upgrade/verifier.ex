defmodule Ouroboros.Upgrade.Verifier do
  @moduledoc """
  Fail-closed policy checks for fast-lane BEAM artifacts.

  The fast lane can replace agent behavior, but not the modules that enforce this
  lane's own guarantees, the surfaces that trigger it, on-load code, or consolidated
  protocols. The protected set is every `Ouroboros.Upgrade.*` module (verifier,
  executor, coordinator), every `Ouroboros.Storage.*` module (the synced journal
  writer a patch could turn into a silent no-op), every `Ouroboros.Release.*` module
  (the durable lane's authorizer and journal), every `Ouroboros.Control.*` module
  (which decides what is patched at all), every `Ouroboros.Gateway.*` module (the
  operator surface, where an auth check that can be hot-patched is no auth at all),
  every `Ouroboros.Agent.Effects.*` module and every `Ouroboros.Orchestration.*`
  module (the forge and deploy entry points a patch could call on an agent's behalf),
  `Ouroboros.Runtime.Capabilities` (the operator admission surface for forged
  capabilities), every `Ouroboros.Mesh.*` module (where deployed capabilities start),
  every `Ouroboros.Provider.Native.*` module and `Ouroboros.Provider.Native` itself
  (path containment, SafeWrite, and the sandbox the native loop consults), every
  `Ouroboros.Workspace.*` module and `Ouroboros.Workspace` itself (the admission
  lease the file tools sit on), and the application root and its registry owner.

  Detection is a policy gate, not a security sandbox. On-load functions are detected
  soundly by asking the code server to prepare the batch. NIF loading is detected only
  as a static import of `:erlang.load_nif/2`; a module that resolves that call at
  runtime is not detected, and any accepted BEAM already runs with ambient VM
  authority.

  A `:introduce` beam is held to every gate a `:replace` beam is held to, plus two of
  its own. The module must be genuinely absent from this VM — unloaded, unreachable on
  the code path, and not something the journal already expects to be present — and its
  name must live under `Ouroboros.Capability.`, the namespace `Ouroboros.Mesh` already
  reserves for modules forged at runtime. That namespace is a policy boundary and
  nothing more: an introduced module is not sandboxed, is not less privileged than a
  replacement, and can do anything any other loaded module can do. Its only guarantee is
  that a new module cannot silently take the name of an existing one.
  """

  alias Ouroboros.Upgrade.{Artifact, Beam}

  @protected_modules [
    Ouroboros.Application,
    Ouroboros.Application.RegistryOwner,
    # The effect API itself, not only its `Runner`: the forge/deploy actions live here.
    Ouroboros.Agent.Effects,
    # The public mesh surface carries the startable-module allowlist.
    Ouroboros.Mesh,
    Ouroboros.Runtime.Capabilities,
    # Containment the native loop and workspace leases enforce: a signed replacement
    # of Paths or SafeWrite is a signed replacement of the write fence.
    Ouroboros.Provider.Native,
    Ouroboros.Workspace
  ]
  @protected_prefixes [
    "Elixir.Ouroboros.Upgrade.",
    "Elixir.Ouroboros.Release.",
    "Elixir.Ouroboros.Storage.",
    "Elixir.Ouroboros.Control.",
    "Elixir.Ouroboros.Gateway.",
    "Elixir.Ouroboros.Agent.Effects.",
    "Elixir.Ouroboros.Orchestration.",
    "Elixir.Ouroboros.Mesh.",
    "Elixir.Ouroboros.Provider.Native.",
    "Elixir.Ouroboros.Workspace."
  ]
  @introduce_prefix "Elixir.Ouroboros.Capability."

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

      not Enum.all?(modules, &(&1.disposition in [:replace, :introduce])) ->
        {:error, :invalid_disposition}

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

  defp verify_module(%Beam{disposition: :replace} = beam, expected_modules) do
    verify_replacement(beam, expected_modules)
  rescue
    error -> {:error, {:module_verification_failed, beam.module, error}}
  end

  defp verify_module(%Beam{disposition: :introduce} = beam, expected_modules) do
    verify_introduction(beam, expected_modules)
  rescue
    error -> {:error, {:module_verification_failed, beam.module, error}}
  end

  defp verify_module(%Beam{} = beam, _expected_modules) do
    {:error, {:invalid_disposition, beam.module, beam.disposition}}
  end

  defp verify_replacement(%Beam{} = beam, expected_modules) do
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
  end

  # Every gate the replacement path applies to a *new* binary applies here too. What is
  # missing is only what a pre-image would have been checked for; what is added is proof
  # that this really is an introduction and that its name is one the policy allows to
  # appear from nowhere.
  defp verify_introduction(%Beam{} = beam, expected_modules) do
    with :ok <- allowed_module(beam.module),
         :ok <- introducible_module(beam.module),
         :ok <- introduction_shape(beam),
         :ok <- module_absent(beam.module, expected_modules),
         false <- :code.is_sticky(beam.module),
         false <- :erlang.check_old_code(beam.module),
         {:ok, new_info} <- Beam.inspect_binary(beam.binary),
         true <- new_info.module == beam.module,
         true <- Beam.sha256(beam.binary) == beam.sha256,
         true <- new_info.md5 == beam.md5,
         true <- new_info.vsn == beam.vsn,
         false <- new_info.on_load?,
         false <- new_info.nif?,
         false <- new_info.protocol? do
      :ok
    else
      true -> {:error, {:forbidden_beam_feature, beam.module}}
      false -> {:error, {:module_verification_failed, beam.module}}
      {:error, reason} -> {:error, reason}
      actual -> {:error, {:module_verification_failed, beam.module, actual}}
    end
  end

  defp introduction_shape(%Beam{} = beam) do
    if is_nil(beam.old_filename) and is_nil(beam.old_binary) and is_nil(beam.old_sha256) and
         is_nil(beam.old_md5) and is_nil(beam.old_vsn) and beam.stateful == false and
         is_nil(beam.migration_extra) do
      :ok
    else
      {:error, {:invalid_introduction, beam.module}}
    end
  end

  defp introducible_module(module) do
    if String.starts_with?(Atom.to_string(module), @introduce_prefix) do
      :ok
    else
      {:error, {:capability_namespace_required, module}}
    end
  end

  # "Absent" has to mean absent to every path that could resurrect the name: the module
  # table, the code path a later `Code.ensure_loaded/1` would search, and this node's own
  # record of what it expects to be loaded. An expectation of absence, left by a
  # rolled-back introduction, is the one entry that does not contradict a new one.
  defp module_absent(module, expected_modules) do
    cond do
      :code.which(module) != :non_existing -> {:error, {:module_already_present, module}}
      :code.get_object_code(module) != :error -> {:error, {:module_already_present, module}}
      true -> expected_absent(module, Map.get(expected_modules, module))
    end
  end

  defp expected_absent(_module, nil), do: :ok
  defp expected_absent(_module, %{sha256: :non_existing, md5: :non_existing}), do: :ok
  defp expected_absent(module, _present), do: {:error, {:module_already_present, module}}

  defp allowed_module(module) do
    name = Atom.to_string(module)

    if module in @protected_modules or String.starts_with?(name, @protected_prefixes) do
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

      # A rolled-back introduction leaves an expectation of absence. There is nothing
      # for a replacement to be a replacement *of*.
      %{sha256: :non_existing, md5: :non_existing} ->
        {:error, {:module_absent, beam.module}}

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
