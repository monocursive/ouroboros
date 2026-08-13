defmodule Ouroboros.Upgrade.ForgeSignerTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Upgrade.Forge.Signer
  alias Ouroboros.Upgrade.{Artifact, Verifier}

  @module Ouroboros.Capability.Signed
  @signer "forge-test-signer"

  setup do
    previous = Application.get_env(:ouroboros, :forge_signer)

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:ouroboros, :forge_signer)
      else
        Application.put_env(:ouroboros, :forge_signer, previous)
      end

      unload(@module)
    end)

    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, public_key: public_key, private_key: private_key}
  end

  test "the shipped default refuses to sign anything" do
    assert {Signer.Deny, []} = Signer.configured()
    assert Signer.Deny.sign("payload", @signer) == {:error, :signing_denied}
    assert Signer.Deny.sign(<<>>, "") == {:error, :signing_denied}

    # A signer that is configured but has no key is a refusal too, not a silent no-op.
    Application.put_env(:ouroboros, :forge_signer, Signer.Local)
    assert {Signer.Local, []} = Signer.configured()
    assert Signer.Local.sign("payload", @signer) == {:error, :private_key_not_configured}

    Application.put_env(:ouroboros, :forge_signer, {Signer.Local, private_key: "too short"})
    assert Signer.Local.sign("payload", @signer) == {:error, :invalid_private_key}
  end

  test "a Local signature is one the verifier accepts", context do
    artifact = artifact!()
    payload = Artifact.signing_payload(artifact, @signer)

    assert {:ok, signature} =
             Signer.Local.sign(payload, @signer, private_key: context.private_key)

    assert byte_size(signature) == 64

    signed = %{artifact | signature: %{signer: @signer, value: signature}}
    policy = [trusted_signers: %{@signer => context.public_key}]

    assert :ok = Verifier.verify(signed, policy)

    # The same signature under a policy that does not name this signer is worth nothing,
    # and `allow_unsigned` does not soften it: an artifact that carries a signature must
    # carry a trusted one.
    assert {:error, {:untrusted_signer, @signer}} =
             Verifier.verify(signed, trusted_signers: %{"someone-else" => context.public_key})

    assert {:error, {:untrusted_signer, @signer}} = Verifier.verify(signed, allow_unsigned: true)

    {other_public_key, _other_private_key} = :crypto.generate_key(:eddsa, :ed25519)

    assert {:error, {:invalid_signature, @signer}} =
             Verifier.verify(signed, trusted_signers: %{@signer => other_public_key})
  end

  test "one flipped byte in the beam binary invalidates the artifact", context do
    artifact = artifact!()
    payload = Artifact.signing_payload(artifact, @signer)
    {:ok, signature} = Signer.Local.sign(payload, @signer, private_key: context.private_key)
    signed = %{artifact | signature: %{signer: @signer, value: signature}}
    policy = [trusted_signers: %{@signer => context.public_key}]

    assert :ok = Verifier.verify(signed, policy)

    [beam] = signed.modules
    tampered = %{signed | modules: [%{beam | binary: flip_byte(beam.binary)}]}

    # The hash in the manifest is what the signature covers, so altered bytes fail before
    # the signature is even consulted. Either way the artifact is refused.
    assert {:error, reason} = Verifier.verify(tampered, policy)
    refute reason == :ok

    # Rewriting the manifest instead of the bytes is what the signature is *for*: every
    # field below travels inside the signed payload.
    for tamper <- [
          fn signed -> %{signed | epoch: signed.epoch + 1} end,
          fn signed -> %{signed | metadata: %{forge: %{author: "somebody-else"}}} end,
          fn signed -> %{signed | id: "rewritten-artifact-id"} end,
          fn signed -> %{signed | signature: %{signer: "other-name", value: signature}} end
        ] do
      rewritten = tamper.(signed)

      assert {:error, {tag, _signer}} = Verifier.verify(rewritten, policy)
      assert tag in [:invalid_signature, :untrusted_signer]
    end
  end

  test "the configured signer is the one the forge would use", context do
    Application.put_env(
      :ouroboros,
      :forge_signer,
      {Signer.Local, private_key: context.private_key}
    )

    assert {Signer.Local, private_key: _key} = Signer.configured()

    artifact = artifact!()
    payload = Artifact.signing_payload(artifact, @signer)

    assert {:ok, signature} = Signer.Local.sign(payload, @signer)
    signed = %{artifact | signature: %{signer: @signer, value: signature}}
    assert :ok = Verifier.verify(signed, trusted_signers: %{@signer => context.public_key})

    # Nonsense configuration falls back to refusing rather than to trusting.
    Application.put_env(:ouroboros, :forge_signer, "not-a-module")
    assert {Signer.Deny, []} = Signer.configured()
  end

  defp artifact! do
    binary = compile_capability!()

    {:ok, artifact} =
      Artifact.build([{@module, binary, disposition: :introduce}],
        epoch: System.unique_integer([:positive, :monotonic]),
        metadata: %{forge: %{author: "test-agent"}}
      )

    artifact
  end

  defp compile_capability! do
    source = """
    defmodule #{inspect(@module)} do
      @vsn 1
      def hello, do: :world
    end
    """

    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)
    [{@module, binary}] = Code.compile_string(source, "signed_capability.ex")
    Code.put_compiler_option(:ignore_module_conflict, previous)

    # Compiling loads. An introduction is only verifiable against a VM that has never
    # seen the name.
    unload(@module)
    binary
  end

  defp flip_byte(binary) do
    offset = div(byte_size(binary), 2)
    <<prefix::binary-size(^offset), byte, suffix::binary>> = binary
    <<prefix::binary, Bitwise.bxor(byte, 1), suffix::binary>>
  end

  defp unload(module) do
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end
end
