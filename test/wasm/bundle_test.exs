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

    test "the file is self-describing: magic, version, and three lengths", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      assert <<"OUROWASM", 2::8, envelope_len::32, precompiled_len::32, component_len::32,
               rest::binary>> = bundle

      assert component_len == byte_size(@bytes)
      # W8. Zero is "the source form only", which is what a manifest with no `precompiled`
      # block means and what every node could always run.
      assert precompiled_len == 0
      assert byte_size(rest) == envelope_len + precompiled_len + component_len

      envelope = binary_part(rest, 0, envelope_len)
      assert {:ok, fields} = JSON.decode(envelope)
      assert Enum.sort(Map.keys(fields)) == ["bundle", "manifest", "signature", "signer"]
      assert fields["signer"] == @signer

      # The big half is raw. A bundle whose component were base64 inside the envelope
      # would be a third larger and would hand a JSON parser sixteen mebibytes.
      assert binary_part(rest, envelope_len + precompiled_len, component_len) == @bytes
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
      header = <<"OUROWASM", 2::8, 64 * 1024 * 1024::32, 0::32, 1::32>>

      assert {:error, {:envelope_too_large, 67_108_864, 65_536}} = Bundle.decode(header)
    end

    test "a component length above the component cap is refused before the slice is taken" do
      over = Bundle.max_component_bytes() + 1
      header = <<"OUROWASM", 2::8, 32::32, 0::32, over::32>>

      assert {:error, {:component_too_large, ^over, _cap}} = Bundle.decode(header)
    end

    test "an empty envelope or an empty component is refused" do
      assert {:error, :empty_envelope} = Bundle.decode(<<"OUROWASM", 2::8, 0::32, 0::32, 1::32>>)
      assert {:error, :empty_component} = Bundle.decode(<<"OUROWASM", 2::8, 1::32, 0::32, 0::32>>)

      # W8. A precompiled section past its own ceiling is refused before its slice is taken
      # too, and the ceiling is the component's times a stated multiple rather than a second
      # number that could drift from it.
      over = Bundle.max_precompiled_bytes() + 1

      assert {:error, {:precompiled_too_large, ^over, _cap}} =
               Bundle.decode(<<"OUROWASM", 2::8, 32::32, over::32, 1::32>>)
    end

    # M32. The version byte is matched as a literal in the clause that reads the two
    # lengths, and the earlier test only reached the *fallback* clause because its input was
    # too short. This one is a whole, well-formed file whose only difference is the version.
    test "a fully framed file from a future version is refused, not read", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      <<"OUROWASM", 2::8, rest::binary>> = bundle
      future = "OUROWASM" <> <<3::8>> <> rest

      assert byte_size(future) == byte_size(bundle)

      assert {:error, {:unsupported_bundle_version, 3}} = Bundle.decode(future)
      assert {:error, {:unsupported_bundle_version, 3}} = Bundle.verify(future, [])
    end

    test "something that is not one of these files is refused by its first eight bytes" do
      assert {:error, :not_a_bundle} = Bundle.decode(<<"NOTAWASM", 2::8, 1::32, 0::32, 1::32>>)

      assert {:error, {:unsupported_bundle_version, 3}} =
               Bundle.decode(<<"OUROWASM", 3::8, 0::32>>)

      # W8 bumped the format. A file written by a build before it is refused by version and
      # not read: format 1 has a shorter header and a manifest missing the field the signed
      # half now carries, so reconstructing one could only ever fail — and "your file is from
      # a build before W8" sends an operator somewhere useful, where a fixed point that failed
      # for no stated reason would not.
      assert {:error, {:unsupported_bundle_version, 1}} =
               Bundle.decode(<<"OUROWASM", 1::8, 32::32, 1::32>>)

      assert {:error, {:invalid_bundle, _}} = Bundle.decode(:not_even_a_binary)

      # A truncated *current-version* file is short, not futuristic. Remove the `version !=`
      # guard from the version clause and this reads as `{:unsupported_bundle_version, 2}`,
      # which sends an operator to look for a newer build instead of at a broken copy.
      assert {:error, {:truncated_bundle, 12}} =
               Bundle.decode(<<"OUROWASM", 2::8, 0::8, 0::8, 0::8>>)
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

      # M8. The number in the refusal is the **encoded** length, which is the whole point of
      # the check: it is made from the length of the string in hand, before a decode of it
      # allocates anything. Delete the pre-decode bound and this still refuses — the decoded
      # ceiling catches it — but it refuses at 40 000 having first built 40 000 bytes from a
      # value somebody else chose the size of.
      oversize = Base.encode64(:binary.copy("m", 40_000))

      assert {:error, {:field_too_large, :manifest, encoded}} =
               rebuild(bundle, &Map.put(&1, "manifest", oversize))

      assert encoded == byte_size(oversize)
      assert encoded > 40_000
    end
  end

  describe "the manifest term, which arrives from a file" do
    # H1. `term_to_binary/2` can deflate its output and `binary_to_term/2` inflates it
    # transparently — `:safe` included — so the ceiling on the *encoded* field said nothing
    # about what a decode allocates. Forty-two kibibytes of zlib was a sixteen-million
    # element list built inside `verify/2`, which is what `wasm.deploy` reaches at
    # `:operate`, before a single trust check had run.
    test "a compressed manifest is refused without being inflated", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      bomb = :erlang.term_to_binary(%{id: List.duplicate(0, 16_000_000)}, compressed: 9)
      assert byte_size(bomb) < 64 * 1024

      hostile = reframe(bundle, &Map.put(&1, "manifest", Base.encode64(bomb)))
      assert byte_size(hostile) < 64 * 1024

      assert {:error, :compressed_manifest} = Bundle.decode(hostile)

      # And the same, through the entry point a socket actually reaches.
      assert {:error, :compressed_manifest} = Bundle.verify(hostile, context.trust_policy)

      # Measured rather than asserted about: delete the tag-80 clause from `uncompressed/1`
      # and this process grows to hundreds of megabytes decoding a file smaller than a
      # screenshot.
      assert grew_by(fn -> Bundle.verify(hostile, context.trust_policy) end) < 4 * 1024 * 1024
    end

    test "the encoder never writes a compressed term, so refusing one costs nothing",
         context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      <<"OUROWASM", 2::8, len::32, _::32, _::32, rest::binary>> = bundle
      {:ok, %{"manifest" => manifest}} = JSON.decode(binary_part(rest, 0, len))

      assert <<131, tag, _::binary>> = Base.decode64!(manifest)
      refute tag == 80
    end

    # The second bound, on what the decode *allocated*. Uncompressed terms are not
    # size-preserving either: a byte list is one byte an element on the wire and a cons cell
    # — sixteen bytes — in the heap, so a field comfortably under the encoded ceiling still
    # costs sixteen times it. Delete `bounded_term/1` and this decodes happily.
    test "a manifest that is small encoded and large decoded is refused", context do
      {:ok, bundle} = Bundle.encode(signed!(context), @bytes)

      # `STRING_EXT`: thirty thousand elements, thirty thousand bytes, and half a mebibyte
      # of heap on the other side.
      fat = :erlang.term_to_binary(%{id: :binary.bin_to_list(:binary.copy(<<1>>, 30_000))})

      assert byte_size(fat) < 32 * 1024
      assert :erts_debug.flat_size(:erlang.binary_to_term(fat)) * 8 > 128 * 1024

      assert {:error, {:manifest_too_large, heap, ceiling}} =
               reframe(bundle, &Map.put(&1, "manifest", Base.encode64(fat))) |> Bundle.decode()

      assert heap > ceiling
      assert ceiling == 128 * 1024

      # A real manifest — the largest this build can produce, with a full eval spec and a
      # 16 KiB start config — is nowhere near it, because its bulk is binaries.
      assert :erts_debug.flat_size(Artifact.manifest(signed!(context))) * 8 < 128 * 1024
    end

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
    Bundle.decode(reframe(bundle, mutate))
  end

  defp swap_component(bundle, replacement) do
    <<"OUROWASM", 2::8, envelope_len::32, precompiled_len::32, component_len::32, rest::binary>> =
      bundle

    ^component_len = byte_size(replacement)
    head = binary_part(rest, 0, envelope_len + precompiled_len)

    "OUROWASM" <>
      <<2::8, envelope_len::32, precompiled_len::32, component_len::32>> <> head <> replacement
  end

  # Re-frames a bundle with a mutated envelope and hands back the *file*, where `rebuild/2`
  # hands back the decode. Same arithmetic, different question.
  defp reframe(bundle, mutate) do
    <<"OUROWASM", 2::8, envelope_len::32, precompiled_len::32, component_len::32, rest::binary>> =
      bundle

    envelope = binary_part(rest, 0, envelope_len)
    tail = binary_part(rest, envelope_len, precompiled_len + component_len)

    {:ok, fields} = JSON.decode(envelope)
    replaced = fields |> mutate.() |> JSON.encode!()

    "OUROWASM" <>
      <<2::8, byte_size(replaced)::32, precompiled_len::32, component_len::32>> <>
      replaced <> tail
  end

  # How much heap one call grew, measured in a process of its own so nothing this test
  # already holds is counted.
  defp grew_by(fun) do
    parent = self()

    {pid, ref} =
      spawn_monitor(fn ->
        _result = fun.()
        {:memory, memory} = Process.info(self(), :memory)
        send(parent, {:grew, memory})
      end)

    receive do
      {:grew, memory} ->
        receive do
          {:DOWN, ^ref, _, _, _} -> :ok
        after
          1_000 -> :ok
        end

        memory
    after
      120_000 ->
        Process.exit(pid, :kill)
        flunk("the decode did not finish in 120s")
    end
  end

  defp interned?(name) do
    _atom = String.to_existing_atom(name)
    true
  rescue
    ArgumentError -> false
  end
end
