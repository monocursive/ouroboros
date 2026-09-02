defmodule Ouroboros.Wasm.BundleTest do
  # Async: nothing here touches the helper, the store, a register, or application
  # environment. A bundle is bytes in and bytes out.
  use ExUnit.Case, async: true

  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Bundle

  @signer "wasm-bundle-test-key"

  # Exactly as long as the word `placeholder`, so it can be spliced into an encoded term
  # without disturbing the external term format's own length prefixes.
  @unknown_atom "zqxjvwmbkph"

  @bytes "\0asm\x01\x00\x00\x00 a component this test never runs"

  setup do
    {public, secret} = :crypto.generate_key(:eddsa, :ed25519)

    %{
      public: public,
      secret: secret,
      trust_policy: [allow_unsigned: false, trusted_signers: %{@signer => public}]
    }
  end

  describe "the round trip" do
    test "one file carries the manifest, the signature and the bytes, and gives them back",
         context do
      artifact = signed!(context)

      assert {:ok, bundle} = Bundle.encode(artifact, @bytes)
      assert {:ok, %{artifact: decoded, bytes: bytes}} = Bundle.decode(bundle)

      assert bytes == @bytes
      # The manifest is what a signature covers, so it is the equality that matters:
      # every field, in the right place, including the eval spec's tuples and atoms.
      assert Artifact.manifest(decoded) == Artifact.manifest(artifact)
      assert decoded.signature == artifact.signature

      # And the reconstruction is good enough for the signature to verify against it,
      # which is the only claim the round trip is actually making.
      assert :ok = Wasm.Verifier.verify(decoded, bytes, context.trust_policy)
    end

    test "the prefix plus the caller's own bytes is the same file the encoder writes",
         context do
      artifact = signed!(context)

      assert {:ok, prefix} = Bundle.prefix(artifact)
      assert {:ok, bundle} = Bundle.encode(artifact, @bytes)

      # This is what `ouro wasm sign` does: the node answers the prefix and the client
      # appends the component it uploaded. If these two ever differ, the client is
      # composing a format it does not implement.
      assert prefix <> @bytes == bundle
    end

    test "the file is self-describing: magic, version, and two lengths", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      assert <<"OUROWASM", 1::8, envelope_len::32, component_len::32, rest::binary>> = bundle
      assert component_len == byte_size(@bytes)
      assert byte_size(rest) == envelope_len + component_len

      envelope = binary_part(rest, 0, envelope_len)
      assert {:ok, fields} = JSON.decode(envelope)
      assert Enum.sort(Map.keys(fields)) == ["bundle", "manifest", "signature", "signer"]
      assert fields["signer"] == @signer

      # The big half is raw. A bundle whose component were base64 inside the envelope
      # would be a third larger and would hand a JSON parser sixteen mebibytes.
      assert binary_part(rest, envelope_len, component_len) == @bytes
    end
  end

  describe "verify/2 — what a bundle cannot talk its way past" do
    test "a trusted signature over the manifest that describes these bytes is admitted",
         context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      assert {:ok, %{artifact: artifact, bytes: @bytes}} =
               Bundle.verify(bundle, context.trust_policy)

      assert artifact.component_sha256 == Artifact.digest(@bytes)
    end

    # Delete the `Verifier.verify/3` call from `Bundle.verify/2` and this is the test that
    # goes green when it should not: the bytes still parse, they are simply not the ones
    # anybody signed.
    test "bytes swapped for different bytes of the same length are refused on the sha",
         context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      swapped = swap_component(bundle, String.duplicate("x", byte_size(@bytes)))

      # The framing is intact — same lengths, same envelope, no trailing data — so nothing
      # about the file is malformed. Only the digest says so.
      assert {:ok, %{bytes: replaced}} = Bundle.decode(swapped)
      assert replaced != @bytes

      assert {:error, {:component_sha256_mismatch, _expected, _actual}} =
               Bundle.verify(swapped, context.trust_policy)
    end

    test "a signature issued over a different manifest is refused", context do
      artifact = unsigned!()
      other = %{artifact | epoch: artifact.epoch + 1}

      # A real signature, correctly formed, over a manifest that is not this one.
      signed = attach(artifact, sign(other, context.secret))

      {:ok, bundle} = Bundle.encode(signed, @bytes)

      assert {:error, {:invalid_signature, @signer}} =
               Bundle.verify(bundle, context.trust_policy)
    end

    test "a signer this node does not trust is refused, however well formed", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      assert {:error, {:untrusted_signer, @signer}} =
               Bundle.verify(bundle, allow_unsigned: false, trusted_signers: %{})

      # And a different key under the same id is not the same signer.
      {other_public, _other_secret} = :crypto.generate_key(:eddsa, :ed25519)

      assert {:error, {:invalid_signature, @signer}} =
               Bundle.verify(bundle,
                 allow_unsigned: false,
                 trusted_signers: %{@signer => other_public}
               )
    end

    test "the trust policy is the reader's; a bundle carries none", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      # The same file, two readers, two answers. That is the whole point of the policy
      # living outside the bundle.
      assert {:ok, _admitted} = Bundle.verify(bundle, context.trust_policy)
      assert {:error, _refused} = Bundle.verify(bundle, [])
    end
  end

  describe "every bound, before anything is parsed" do
    test "trailing data is a refusal, not a suffix nobody looked at", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      # Delete `exact_length/3`'s `actual > expected` clause and this goes green: the file
      # would parse to the same artifact with a region nobody described riding along.
      assert {:error, {:trailing_data, 1}} = Bundle.decode(bundle <> "!")

      assert {:error, {:trailing_data, 4096}} =
               Bundle.decode(bundle <> String.duplicate("!", 4096))
    end

    test "a file shorter than it says it is is refused rather than read up to its claim",
         context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      short = binary_part(bundle, 0, byte_size(bundle) - 1)
      assert {:error, {:truncated_bundle, _actual, _expected}} = Bundle.decode(short)

      # Shorter than the header itself is named differently, because there is not yet a
      # claim to compare against.
      assert {:error, {:truncated_bundle, 4}} = Bundle.decode(binary_part(bundle, 0, 4))
    end

    test "an envelope length above the ceiling is refused before the slice is taken" do
      # No envelope and no component exist here at all — the file is seventeen bytes and a
      # claim. Delete the `envelope_len > @max_envelope_bytes` clause and `binary_part/3`
      # is asked for 64 MiB of a 17-byte binary.
      header = <<"OUROWASM", 1::8, 64 * 1024 * 1024::32, 1::32>>

      assert {:error, {:envelope_too_large, 67_108_864, 65_536}} = Bundle.decode(header)
    end

    test "a component length above the component cap is refused before the slice is taken" do
      over = Bundle.max_component_bytes() + 1
      header = <<"OUROWASM", 1::8, 32::32, over::32>>

      assert {:error, {:component_too_large, ^over, _cap}} = Bundle.decode(header)
    end

    test "an empty envelope or an empty component is refused" do
      assert {:error, :empty_envelope} = Bundle.decode(<<"OUROWASM", 1::8, 0::32, 1::32>>)
      assert {:error, :empty_component} = Bundle.decode(<<"OUROWASM", 1::8, 1::32, 0::32>>)
    end

    test "something that is not one of these files is refused by its first eight bytes" do
      assert {:error, :not_a_bundle} = Bundle.decode(<<"NOTAWASM", 1::8, 1::32, 1::32>>)

      assert {:error, {:unsupported_bundle_version, 2}} =
               Bundle.decode(<<"OUROWASM", 2::8, 0::32>>)

      assert {:error, {:invalid_bundle, _}} = Bundle.decode(:not_even_a_binary)

      # A truncated *v1* file is short, not futuristic. Remove the `version !=` guard from
      # the version clause and this reads as `{:unsupported_bundle_version, 1}`, which
      # sends an operator to look for a newer build instead of at a broken copy.
      assert {:error, {:truncated_bundle, 12}} =
               Bundle.decode(<<"OUROWASM", 1::8, 0::8, 0::8, 0::8>>)
    end

    test "the envelope is closed, and its two encoded fields are bounded", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      assert {:error, {:unknown_envelope_keys, _}} =
               rebuild(bundle, &Map.put(&1, "extra", "please read me"))

      assert {:error, {:invalid_base64, :manifest}} =
               rebuild(bundle, &Map.put(&1, "manifest", "!!"))

      assert {:error, {:invalid_signature, 3}} =
               rebuild(bundle, &Map.put(&1, "signature", Base.encode64("abc")))

      assert {:error, {:invalid_signer, 0}} = rebuild(bundle, &Map.put(&1, "signer", ""))

      assert {:error, {:field_too_large, :manifest, _}} =
               rebuild(bundle, &Map.put(&1, "manifest", Base.encode64(:binary.copy("m", 40_000))))
    end
  end

  describe "the manifest term, which arrives from a file" do
    test "an atom this node has never interned is refused rather than created", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      # The atom is not written as a literal anywhere in this file, because writing one
      # interns it at compile time and there would be nothing left to prove. It is spliced
      # into the encoded term over a same-length placeholder instead.
      refute interned?(@unknown_atom), "this test is only meaningful while the atom is unknown"

      exotic =
        :erlang.term_to_binary(%{
          id: "x",
          epoch: 1,
          name: "x",
          component_sha256: String.duplicate("a", 64),
          world: Wasm.world(),
          imports: [],
          size: 1,
          created_at: "now",
          metadata: %{author: "a", note: :placeholder}
        })

      exotic = :binary.replace(exotic, "placeholder", @unknown_atom)

      # `:safe` is the whole of the defence. Delete it from `manifest_term/1` and the decode
      # succeeds far enough to intern this atom, in a table nothing garbage collects, filled
      # by whoever wrote the file.
      assert {:error, :unreadable_manifest} =
               rebuild(bundle, &Map.put(&1, "manifest", Base.encode64(exotic)))

      refute interned?(@unknown_atom), "a bundle must not be able to grow the atom table"
    end

    test "a manifest carrying a key this build has no home for is refused", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)
      manifest = signed!(context) |> Artifact.manifest() |> Map.put(:metadata, %{author: "a"})

      # One key the struct has no field for. Without the `@manifest_keys` check the struct
      # would still build — the extra claim simply dropped — and a reader downstream would
      # be verifying a signature over a manifest that is not the one in the file.
      extra = Map.put(manifest, :extra_claim, "trust me")

      assert {:error, {:unknown_manifest_keys, _}} =
               rebuild(
                 bundle,
                 &Map.put(&1, "manifest", Base.encode64(:erlang.term_to_binary(extra)))
               )
    end

    test "a manifest missing a key is refused by the same fixed point", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)
      manifest = signed!(context) |> Artifact.manifest() |> Map.delete(:created_at)

      # Delete the `Artifact.manifest(artifact) != manifest` comparison in `rebuild/1` and
      # this becomes an artifact with `created_at: nil` whose signature check then fails
      # with `{:invalid_signature, _}` — a true refusal for the wrong reason, which is how
      # a reconstruction defect hides as a crypto one.
      assert {:error, :manifest_not_reconstructible} =
               rebuild(
                 bundle,
                 &Map.put(&1, "manifest", Base.encode64(:erlang.term_to_binary(manifest)))
               )
    end

    test "a manifest that is not a map at all is refused", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      assert {:error, {:invalid_manifest, _}} =
               rebuild(
                 bundle,
                 &Map.put(
                   &1,
                   "manifest",
                   Base.encode64(:erlang.term_to_binary(["not", "a", "map"]))
                 )
               )
    end
  end

  describe "encoding refuses what it could not later verify" do
    test "an unsigned manifest is not a bundle" do
      assert {:error, :signature_required} = Bundle.encode(unsigned!(), @bytes)
      assert {:error, :signature_required} = Bundle.prefix(unsigned!())
    end

    test "bytes the manifest does not describe are refused where the mistake is made",
         context do
      artifact = signed!(context)

      assert {:error, {:component_size_mismatch, _, _}} = Bundle.encode(artifact, @bytes <> "!")

      assert {:error, {:component_sha256_mismatch, _}} =
               Bundle.encode(artifact, String.duplicate("y", byte_size(@bytes)))
    end
  end

  ## Helpers

  defp signed!(context), do: attach(unsigned!(), sign(unsigned!(), context.secret))

  # One fixed manifest, so `unsigned!/0` called twice is the same manifest and a signature
  # over one verifies against the other. `Artifact.build/2` stamps `created_at` from the
  # clock and generates an id, so both are pinned here.
  defp unsigned! do
    {:ok, artifact} =
      Artifact.build(@bytes,
        id: "bundle-test-artifact",
        name: "greeter",
        epoch: 42,
        imports: ["log"],
        author: "test-agent",
        eval: %{
          probes: [%{input: %{"greet" => "world"}, expect: {:contains, "greet"}}],
          budget_ms: 1_000,
          required: :all
        },
        start: %{id: "wasm/greeter", config: ~s({"a":1})}
      )

    %{artifact | created_at: "2026-01-01T00:00:00.000000Z"}
  end

  defp sign(artifact, secret) do
    payload = Artifact.signing_payload(artifact, @signer)
    :crypto.sign(:eddsa, :none, payload, [secret, :ed25519])
  end

  defp attach(artifact, value) do
    {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer, value: value})
    signed
  end

  # Re-frames a bundle with a mutated envelope, keeping both lengths honest so that what
  # the test is exercising is the envelope's own checks rather than the framing's.
  defp rebuild(bundle, mutate) do
    <<"OUROWASM", 1::8, envelope_len::32, component_len::32, rest::binary>> = bundle
    envelope = binary_part(rest, 0, envelope_len)
    component = binary_part(rest, envelope_len, component_len)

    {:ok, fields} = JSON.decode(envelope)
    replaced = fields |> mutate.() |> JSON.encode!()

    Bundle.decode(
      "OUROWASM" <> <<1::8, byte_size(replaced)::32, component_len::32>> <> replaced <> component
    )
  end

  defp swap_component(bundle, replacement) do
    <<"OUROWASM", 1::8, envelope_len::32, component_len::32, rest::binary>> = bundle
    ^component_len = byte_size(replacement)
    envelope = binary_part(rest, 0, envelope_len)

    "OUROWASM" <> <<1::8, envelope_len::32, component_len::32>> <> envelope <> replacement
  end

  defp interned?(name) do
    _atom = String.to_existing_atom(name)
    true
  rescue
    ArgumentError -> false
  end
end
