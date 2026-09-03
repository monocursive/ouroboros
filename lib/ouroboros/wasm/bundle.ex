defmodule Ouroboros.Wasm.Bundle do
  @moduledoc """
  One file an operator can move around: the signed manifest, its signature, and the
  component bytes (docs/WASM.md §7.6, C5).

  Lane W's three durable halves normally travel separately — the manifest is a struct,
  the signature is an envelope on it, and the bytes are content-addressed in
  `Ouroboros.Wasm.Store`. That is the right shape *inside* a cluster and the wrong shape
  for a person: `ouro wasm sign` produces something on a laptop and `ouro wasm deploy`
  consumes it somewhere else, and "somewhere else" is reached by `scp`, not by `:erpc`.
  A bundle is that one thing, with the extension `.ouro-wasm`.

  ## Nothing in it is trusted before `verify/2`

  A bundle read from disk is attacker-controlled input, exactly like a component. So it
  carries no authority of its own and this module invents no check of its own:

    * the sha binds the bytes (`Ouroboros.Wasm.Verifier.verify/3` recomputes it),
    * the signature binds the manifest (`Ouroboros.Wasm.Artifact.signing_payload/2` is
      re-derived from the *reconstructed* manifest, never read out of the file),
    * the trust policy binds the signer, and it is the reading node's own policy.

  Swap the component bytes for a different component of the same length and the sha check
  refuses it. Edit one byte of the manifest and the signature refuses it. Sign it with a
  key nobody trusts and the trust policy refuses it. There is no fourth thing a bundle
  could say that anybody here believes.

  ## The framing, and why the big half is not base64

  A fixed 21-byte header, a bounded JSON envelope, an optional precompiled artifact, and then
  the component bytes raw:

      offset  0   "OUROWASM"                  magic
      offset  8   0x02                        format version, exactly
      offset  9   envelope length             uint32, big-endian, <= #{64 * 1024}
      offset 13   precompiled length          uint32, big-endian, 0 or <= the precompiled cap
      offset 17   component length            uint32, big-endian, <= the component cap
      offset 21   envelope                    JSON, UTF-8
              …   precompiled                 exactly `precompiled length` bytes (may be none)
              …   component                   exactly `component length` bytes
              …   nothing. Trailing data is a refusal.

  ## Two forms, one file (W8, D22)

  Format 2 carries a second length-prefixed section: wasmtime's serialized form of the same
  component, produced at sign time by `ouro-wasm precompile` (D23). It is present exactly when
  the signed manifest declares a `precompiled` block, and `verify/2` binds **each form to its
  own sha** — the manifest's `component_sha256` to the component bytes, its `precompiled.sha256`
  to the artifact bytes — because a signature over one digest says nothing about bytes beside it.
  A bundle carrying a section the manifest does not declare, or declaring one it does not carry,
  is refused: those are two statements about one file that disagree.

  The precompiled section sits **before** the component rather than after it, which is not a
  taste. `wasm.sign` answers with the bundle's *prefix* and the client appends the exact bytes
  it uploaded (§7.6): the client holds the component and has never seen the artifact, so the
  only ordering in which the client still composes nothing is the one where everything it did
  not produce comes first. Format 1 files are refused by version — the manifest's signed half
  gained a field, so a format-1 bundle could not have reconstructed anyway, and "your file is
  from a build before W8" is a better answer than a fixed point that fails for no stated reason.

  The envelope is JSON because it is a few hundred bytes that a person may want to read
  with `head`, and the two fields in it that are not text — the manifest term and the
  64-byte signature — are base64 inside it. The **component is not**: base64 of sixteen
  mebibytes is twenty-one mebibytes of decoding work handed to a parser by whoever wrote
  the file, to save nobody anything. Length-prefixed raw bytes at a known offset cost one
  `binary_part/3`.

  Every field is bounded *before* it is parsed. The header is read from a prefix, the two
  lengths are checked against their ceilings before either slice is taken, and the total
  size must be exactly the header plus the two — so a file that is one byte longer than
  it says it is is refused rather than read up to its claim.

  ## Why the manifest is a term and not JSON

  What a signature covers is
  `:erlang.term_to_binary({:ouroboros_wasm_v1, signer, manifest}, [:deterministic])`
  (C4). A manifest that round-tripped through JSON would come back with string keys,
  without the eval spec's tuples, and would not re-derive those bytes — the signature
  would be unverifiable against the very manifest it was issued for. So the manifest is
  carried as its own `term_to_binary`, and read back with **`:safe`**: a bundle that
  spells an atom this node has never interned is refused rather than allowed to grow the
  atom table, which is the ordinary reason `binary_to_term/1` on foreign bytes is a
  defect. Nothing legitimate is lost by that, because every atom a signed eval spec can
  contain is one `Ouroboros.Gateway.Methods` already held as a literal when it built the
  spec from a client's JSON.

  Reconstruction is then held to its own fixed point: the struct built out of the decoded
  map must project back — through `Ouroboros.Wasm.Artifact.manifest/1` — to exactly the
  map that was decoded. A field this module put in the wrong place, a key the manifest
  carried that the struct has no home for, or a key it lacks: all three are one comparison
  rather than nine, and none of them can reach a signature check pretending to be sound.
  """

  alias Ouroboros.Wasm.{Artifact, Verifier}

  @extension ".ouro-wasm"

  @magic "OUROWASM"
  @format_version 2
  @header_bytes 21

  # A few hundred bytes in practice: a manifest term, a signer id, and 88 characters of
  # base64. Sixty-four kibibytes is far above every legitimate value — the signer's own
  # start config is bounded at 16 KiB and an eval spec at 16 KiB — and small enough that a
  # hostile envelope is a refusal rather than a parse.
  @max_envelope_bytes 64 * 1024

  # The manifest term itself, after base64 decoding and before `binary_to_term/2`. It is
  # inside the envelope and therefore already bounded by it; stated separately because the
  # thing being bounded is what a term decoder is handed, and that deserves its own number
  # rather than an inherited one.
  @max_manifest_bytes 32 * 1024

  # And what the decoded term may cost this process. The largest manifest this build can
  # legitimately produce — a full twenty-probe eval spec and a 16 KiB start config — is
  # about eight kibibytes of heap, because its bulk is binaries and binaries are cheap on a
  # heap. Sixteen times that is generous for everything real and refuses the shapes that
  # are only large after decoding: a byte list encodes at one byte an element and decodes at
  # sixteen.
  @max_manifest_heap_bytes 128 * 1024

  @word_bytes 8

  # Not a new number. It is the ceiling the signer already holds a lane-W submission to
  # (`:signing_max_artifact_bytes`, `Ouroboros.Upgrade.Signing.Service`), so a bundle can
  # never carry more bytes than a signer would have looked at. A second, independent
  # component cap would be a second place for the two to disagree.
  @default_max_component_bytes 16 * 1024 * 1024

  # What a *precompiled* section may be, as a multiple of the component ceiling. Machine code is
  # bigger than the wasm it came from and the ratio is not constant: measured on this build the
  # 48 KiB reference guest serializes to 258 093 bytes (5.3×, fixed overhead dominating) and the
  # worst shape §7.3 admits — 4 035 787 bytes, 20 000 functions — to 11 092 495 (2.75×). Four
  # times the component ceiling clears the worst measured ratio with half again to spare, and
  # every byte above that is staging ceiling this lane would be spending without deciding to:
  # `Ouroboros.Wasm.Upload` sizes a slot from `max_bytes/0`, so this number is also how much
  # disk one client may park on a node. It was eight, which put an upload slot at 144 MiB and
  # the eight of them at 1152 MiB — a number nobody had chosen (D16, §12).
  @precompiled_multiple 4

  # And what `ouro-wasm` itself will read, mirrored rather than re-derived: the helper caps a
  # precompiled artifact at exactly its own 64 MiB component read cap (`precompiled.rs`,
  # `MAX_PAYLOAD_BYTES`). A bundle that admitted more than the helper will read would be a file
  # this node accepts and cannot use, so the two are held to each other here and pinned by a
  # test against the live `doctor` (`max_precompiled_bytes` under `limits`).
  @helper_precompiled_bytes 64 * 1024 * 1024

  @signature_bytes 64
  @max_signer_bytes 256

  @envelope_keys ["bundle", "manifest", "signer", "signature"]

  # Exactly the keys `Ouroboros.Wasm.Artifact.manifest/1` projects. Listed so a decode
  # reads named fields rather than whatever the map happened to hold, and the fixed-point
  # check below proves the two lists agree.
  @manifest_keys [
    :id,
    :epoch,
    :name,
    :component_sha256,
    :kind,
    :world,
    :imports,
    :size,
    :created_at,
    # W8
    :precompiled,
    :metadata
  ]

  @type decoded :: %{artifact: Artifact.t(), bytes: binary(), precompiled: binary() | nil}

  @doc "The extension one of these files is written under."
  @spec extension() :: String.t()
  def extension, do: @extension

  @doc """
  The largest component a bundle may carry, which is the signer's own submission ceiling.
  """
  @spec max_component_bytes() :: pos_integer()
  def max_component_bytes do
    case Application.get_env(:ouroboros, :signing_max_artifact_bytes) do
      bytes when is_integer(bytes) and bytes > 0 -> bytes
      _unset_or_invalid -> @default_max_component_bytes
    end
  end

  @doc """
  The largest precompiled artifact a bundle may carry (W8).

  Four times the component ceiling — clear of the 2.75× worst measured ratio — and never above
  what `ouro-wasm` will read. Derived from the component ceiling rather than configured beside
  it, so an operator who raises what a signer will look at raises what its output may be in one
  place; capped by the helper's own number, because a bundle this build admits and the helper
  refuses is a file nobody can use.
  """
  @spec max_precompiled_bytes() :: pos_integer()
  def max_precompiled_bytes,
    do: min(max_component_bytes() * @precompiled_multiple, @helper_precompiled_bytes)

  @doc """
  The artifact ceiling `ouro-wasm` itself enforces, mirrored here (W8, M6).

  Public so a test can hold it to the helper's own `doctor` rather than to a comment. If the
  two ever disagree this build admits bundles it cannot load, which is a file an operator moves
  around and a node refuses for a reason neither of them named.
  """
  @spec helper_precompiled_bytes() :: pos_integer()
  def helper_precompiled_bytes, do: @helper_precompiled_bytes

  @doc "The largest legal bundle: both ceilings plus the header and envelope."
  @spec max_bytes() :: pos_integer()
  def max_bytes,
    do: max_component_bytes() + max_precompiled_bytes() + @max_envelope_bytes + @header_bytes

  @doc """
  Encodes one signed artifact and the bytes it describes.

  Refuses bytes the manifest does not describe and a manifest carrying no signature: a
  bundle that could not be verified is a file whose only future is a refusal somewhere
  less convenient than here.
  """
  @spec encode(Artifact.t(), binary(), binary() | nil) :: {:ok, binary()} | {:error, term()}
  def encode(artifact, bytes, precompiled \\ nil)

  def encode(%Artifact{} = artifact, bytes, precompiled)
      when is_binary(bytes) and (is_binary(precompiled) or is_nil(precompiled)) do
    with :ok <- describes?(artifact, bytes),
         {:ok, prefix} <- prefix(artifact, precompiled) do
      {:ok, prefix <> bytes}
    end
  end

  def encode(%Artifact{}, bytes, precompiled) when is_binary(bytes),
    do: {:error, {:invalid_precompiled, describe(precompiled)}}

  def encode(%Artifact{}, bytes, _precompiled),
    do: {:error, {:invalid_component, describe(bytes)}}

  def encode(artifact, _bytes, _precompiled),
    do: {:error, {:invalid_artifact, describe(artifact)}}

  @doc """
  Everything in a bundle except the component: the header and the envelope.

  This exists because of where the two halves are. `wasm.sign` runs on a node that has
  the key and the policy; the operator running `ouro wasm sign` already holds the exact
  bytes they submitted. So the node answers with this — the header, the envelope, and, when
  the signer compiled one, the precompiled artifact the client has never seen — and the
  client writes it followed by the file it read. The header states the component length, so
  the concatenation the client performs is the whole of its knowledge of this format: it
  appends bytes and never composes a manifest.

  `precompiled` must be present exactly when the manifest declares a block, and must be the
  bytes that block's sha names. Both are checked here rather than at the reader: a prefix that
  could only ever be refused is one worth refusing where it is built.
  """
  @spec prefix(Artifact.t(), binary() | nil) :: {:ok, binary()} | {:error, term()}
  def prefix(artifact, precompiled \\ nil)

  def prefix(%Artifact{signature: %{signer: signer, value: value}} = artifact, precompiled)
      when is_binary(signer) and is_binary(value) do
    with :ok <- signed?(artifact),
         :ok <- carries_precompiled?(artifact, precompiled),
         {:ok, envelope} <- envelope(artifact, signer, value) do
      {:ok,
       @magic <>
         <<@format_version::8, byte_size(envelope)::32, precompiled_size(precompiled)::32,
           artifact.size::32>> <>
         envelope <> (precompiled || "")}
    end
  end

  def prefix(%Artifact{}, _precompiled), do: {:error, :signature_required}
  def prefix(artifact, _precompiled), do: {:error, {:invalid_artifact, describe(artifact)}}

  @doc """
  Parses one bundle into the manifest it carries and the bytes beside it.

  Bounds only: this says the file is well formed and internally addressable, never that
  anybody should run it. `verify/2` is what a loading node calls.
  """
  @spec decode(binary()) :: {:ok, decoded()} | {:error, term()}
  def decode(binary) when is_binary(binary) do
    with {:ok, envelope_len, precompiled_len, component_len} <- header(binary),
         :ok <- exact_length(binary, envelope_len, precompiled_len, component_len),
         envelope = binary_part(binary, @header_bytes, envelope_len),
         precompiled = section(binary, @header_bytes + envelope_len, precompiled_len),
         bytes =
           binary_part(binary, @header_bytes + envelope_len + precompiled_len, component_len),
         {:ok, fields} <- envelope_fields(envelope),
         {:ok, artifact} <- artifact(fields),
         :ok <- carries_precompiled?(artifact, precompiled) do
      {:ok, %{artifact: artifact, bytes: bytes, precompiled: precompiled}}
    end
  end

  def decode(other), do: {:error, {:invalid_bundle, describe(other)}}

  @doc """
  Parses a bundle and verifies it against `trust_policy`, yielding what a deploy needs.

  The policy is the **reading** node's — `Ouroboros.Wasm.Rollout.deploy/4` reads its own
  and every target reads its own again. A bundle never carries one, and a caller that
  supplied one for the node it is deploying to would be verifying the sender.
  """
  @spec verify(binary(), keyword()) :: {:ok, decoded()} | {:error, term()}
  def verify(binary, trust_policy \\ [])

  def verify(binary, trust_policy) when is_binary(binary) and is_list(trust_policy) do
    with {:ok, %{artifact: artifact, bytes: bytes, precompiled: precompiled} = decoded} <-
           decode(binary),
         :ok <- Verifier.verify(artifact, bytes, trust_policy),
         # W8. Each form is bound to its own sha. `Verifier.verify/3` binds the component; this
         # binds the artifact beside it, because a signature over one digest says nothing about
         # bytes that merely travelled next to it. A node that skipped this would deserialize
         # machine code nobody signed out of a file that was otherwise perfectly verified.
         :ok <- Verifier.verify_precompiled(artifact, precompiled) do
      {:ok, decoded}
    end
  end

  def verify(binary, trust_policy) when is_binary(binary),
    do: {:error, {:invalid_trust_policy, describe(trust_policy)}}

  def verify(other, _trust_policy), do: {:error, {:invalid_bundle, describe(other)}}

  ## Encoding

  defp describes?(%Artifact{} = artifact, bytes) do
    cond do
      byte_size(bytes) != artifact.size ->
        {:error, {:component_size_mismatch, artifact.size, byte_size(bytes)}}

      Artifact.digest(bytes) != artifact.component_sha256 ->
        {:error, {:component_sha256_mismatch, artifact.component_sha256}}

      true ->
        :ok
    end
  end

  defp signed?(%Artifact{} = artifact) do
    cond do
      not Artifact.signed?(artifact) -> {:error, :signature_required}
      not is_integer(artifact.size) or artifact.size <= 0 -> {:error, :invalid_component_size}
      artifact.size > max_component_bytes() -> {:error, {:component_too_large, artifact.size}}
      true -> :ok
    end
  end

  defp envelope(artifact, signer, value) do
    manifest = :erlang.term_to_binary(Artifact.manifest(artifact), [:deterministic])

    cond do
      byte_size(manifest) > @max_manifest_bytes ->
        {:error, {:manifest_too_large, byte_size(manifest), @max_manifest_bytes}}

      byte_size(signer) > @max_signer_bytes ->
        {:error, {:invalid_signer, byte_size(signer)}}

      true ->
        encoded =
          JSON.encode!(%{
            "bundle" => @format_version,
            "manifest" => Base.encode64(manifest),
            "signer" => signer,
            "signature" => Base.encode64(value)
          })

        if byte_size(encoded) > @max_envelope_bytes,
          do: {:error, {:envelope_too_large, byte_size(encoded), @max_envelope_bytes}},
          else: {:ok, encoded}
    end
  end

  ## Decoding

  # The header is read out of a prefix and both lengths are checked against their ceilings
  # before either slice is taken, so nothing here allocates on a number the file chose.
  defp header(
         <<@magic, @format_version::8, envelope_len::32, precompiled_len::32, component_len::32,
           _rest::binary>>
       ) do
    cond do
      envelope_len == 0 ->
        {:error, :empty_envelope}

      envelope_len > @max_envelope_bytes ->
        {:error, {:envelope_too_large, envelope_len, @max_envelope_bytes}}

      component_len == 0 ->
        {:error, :empty_component}

      component_len > max_component_bytes() ->
        {:error, {:component_too_large, component_len, max_component_bytes()}}

      # Zero means "this bundle carries the source form only", which is every bundle a node
      # without a helper produced and every bundle written with `--no-precompile`.
      precompiled_len > max_precompiled_bytes() ->
        {:error, {:precompiled_too_large, precompiled_len, max_precompiled_bytes()}}

      true ->
        {:ok, envelope_len, precompiled_len, component_len}
    end
  end

  # Guarded on the version, so a *truncated* v1 file falls through to the length clause
  # below rather than being reported as a version this build does not serve. "Your file is
  # from the future" and "your file is cut short" send an operator to different places.
  defp header(<<@magic, version::8, _rest::binary>>) when version != @format_version,
    do: {:error, {:unsupported_bundle_version, version}}

  defp header(binary) when byte_size(binary) < @header_bytes,
    do: {:error, {:truncated_bundle, byte_size(binary)}}

  defp header(_binary), do: {:error, :not_a_bundle}

  # Exactly, not at least. A file that carries more than it declares is a file with a
  # region nobody described, and "the rest of it" is not a field this format has.
  defp exact_length(binary, envelope_len, precompiled_len, component_len) do
    expected = @header_bytes + envelope_len + precompiled_len + component_len

    case byte_size(binary) do
      ^expected -> :ok
      actual when actual < expected -> {:error, {:truncated_bundle, actual, expected}}
      actual -> {:error, {:trailing_data, actual - expected}}
    end
  end

  defp section(_binary, _offset, 0), do: nil
  defp section(binary, offset, length), do: binary_part(binary, offset, length)

  defp precompiled_size(nil), do: 0
  defp precompiled_size(bytes) when is_binary(bytes), do: byte_size(bytes)

  # The manifest declares a precompiled form or it does not, and the file carries one or it does
  # not; the two have to be the same statement. A section nobody signed for is bytes a reader
  # would have to decide what to do with, and a declaration with no section is a manifest whose
  # fast path does not exist in the file that carries it.
  defp carries_precompiled?(%Artifact{precompiled: nil}, nil), do: :ok

  defp carries_precompiled?(%Artifact{precompiled: nil}, bytes) when is_binary(bytes),
    do: {:error, {:unexpected_precompiled, byte_size(bytes)}}

  defp carries_precompiled?(%Artifact{precompiled: %{}}, nil), do: {:error, :missing_precompiled}

  defp carries_precompiled?(%Artifact{precompiled: %{} = block}, bytes) when is_binary(bytes) do
    cond do
      not Artifact.precompiled?(block) ->
        {:error, {:invalid_precompiled, describe(block)}}

      byte_size(bytes) > max_precompiled_bytes() ->
        {:error, {:precompiled_too_large, byte_size(bytes), max_precompiled_bytes()}}

      true ->
        :ok
    end
  end

  defp carries_precompiled?(%Artifact{precompiled: other}, _bytes),
    do: {:error, {:invalid_precompiled, describe(other)}}

  defp envelope_fields(envelope) do
    case JSON.decode(envelope) do
      {:ok, %{"bundle" => @format_version} = fields} -> fields(fields)
      {:ok, %{"bundle" => other}} -> {:error, {:unsupported_bundle_version, describe(other)}}
      {:ok, other} -> {:error, {:invalid_envelope, describe(other)}}
      {:error, reason} -> {:error, {:invalid_envelope, describe(reason)}}
    end
  rescue
    _error -> {:error, :invalid_envelope}
  end

  defp fields(%{"manifest" => manifest, "signer" => signer, "signature" => signature} = envelope)
       when is_binary(manifest) and is_binary(signer) and is_binary(signature) do
    with :ok <- only_envelope_keys(envelope),
         {:ok, term} <- decode64(manifest, :manifest, @max_manifest_bytes),
         {:ok, value} <- decode64(signature, :signature, @signature_bytes) do
      cond do
        signer == "" or byte_size(signer) > @max_signer_bytes ->
          {:error, {:invalid_signer, byte_size(signer)}}

        byte_size(value) != @signature_bytes ->
          {:error, {:invalid_signature, byte_size(value)}}

        true ->
          {:ok, %{manifest: term, signer: signer, signature: value}}
      end
    end
  end

  defp fields(other), do: {:error, {:invalid_envelope, describe(other)}}

  # Closed, like every other envelope this build reads from somebody else. A key nobody
  # named is inert — the signature covers the manifest and nothing else in here — but a
  # bundle carrying one is a bundle written by something that is not this build, and
  # saying so is cheaper than wondering later.
  defp only_envelope_keys(envelope) do
    case Map.keys(envelope) -- @envelope_keys do
      [] -> :ok
      unknown -> {:error, {:unknown_envelope_keys, describe(Enum.sort(unknown))}}
    end
  end

  defp decode64(value, field, max) do
    # Bounded before decoding, not after: base64 is four characters to three bytes, so the
    # encoded length already says how much a decode would allocate.
    if byte_size(value) > div(max + 2, 3) * 4 + 4 do
      {:error, {:field_too_large, field, byte_size(value)}}
    else
      case Base.decode64(value) do
        {:ok, decoded} when byte_size(decoded) <= max -> {:ok, decoded}
        {:ok, decoded} -> {:error, {:field_too_large, field, byte_size(decoded)}}
        :error -> {:error, {:invalid_base64, field}}
      end
    end
  end

  # `:safe` refuses to create atoms and refuses funs, and it is *not* the whole of the
  # answer to "this term came from a file somebody else wrote" — see `manifest_term/1`.
  defp artifact(%{manifest: term, signer: signer, signature: signature}) do
    with {:ok, manifest} <- manifest_term(term),
         {:ok, artifact} <- rebuild(manifest) do
      Artifact.with_signature(artifact, %{signer: signer, value: signature})
    end
  end

  # Three checks, and the order is the whole of it.
  #
  # 1. **Not compressed.** `term_to_binary/2` can deflate its output, and
  #    `binary_to_term/2` inflates it transparently — `:safe` included. So the ceiling
  #    `decode64/3` held the *encoded* length to says nothing about what a decode
  #    allocates: forty-two kibibytes of zlib is a sixteen-million-element list, built
  #    inside `verify/2` — the entry point `wasm.deploy` reaches at `:operate` — before a
  #    single trust check has run. This build's encoder passes `[:deterministic]` and
  #    nothing else, so it never emits tag 80 and refusing it costs nothing that could
  #    legitimately arrive.
  # 2. **Then decode**, under `:safe`, so no atom and no fun is created by a file.
  # 3. **Then bound what was allocated**, not what was read. Uncompressed external terms
  #    are not size-preserving either: thirty kibibytes of `STRING_EXT` is thirty thousand
  #    cons cells, which is half a mebibyte of heap — sixteen times what the field's own
  #    ceiling admitted. `:erts_debug.flat_size/1` measures the decoded term in words and
  #    allocates nothing to do it, so the ceiling below is a statement about this process's
  #    heap rather than about a length somebody else chose.
  defp manifest_term(term) do
    with :ok <- uncompressed(term),
         {:ok, manifest} <- decoded(term) do
      bounded_term(manifest)
    end
  end

  # The external term format is a `131` version byte and then a tag. `80` is `COMPRESSED`.
  defp uncompressed(<<131, 80, _rest::binary>>), do: {:error, :compressed_manifest}
  defp uncompressed(<<131, _tag, _rest::binary>>), do: :ok
  defp uncompressed(_other), do: {:error, :unreadable_manifest}

  defp decoded(term) do
    case :erlang.binary_to_term(term, [:safe]) do
      manifest when is_map(manifest) and not is_struct(manifest) -> {:ok, manifest}
      other -> {:error, {:invalid_manifest, describe(other)}}
    end
  rescue
    _error -> {:error, :unreadable_manifest}
  catch
    _kind, _reason -> {:error, :unreadable_manifest}
  end

  defp bounded_term(manifest) do
    heap = :erts_debug.flat_size(manifest) * @word_bytes

    if heap > @max_manifest_heap_bytes,
      do: {:error, {:manifest_too_large, heap, @max_manifest_heap_bytes}},
      else: {:ok, manifest}
  end

  # Named fields, then one fixed point. The struct is built out of the keys this module
  # names, and it is kept only if projecting it back through `Artifact.manifest/1` yields
  # exactly the map that was decoded — which is false for a manifest carrying a key this
  # build has no home for, false for one missing a key, and false for a field this
  # function put in the wrong place. One comparison, and no signature check downstream can
  # be handed a manifest that is not the one in the file.
  defp rebuild(manifest) do
    artifact = %Artifact{
      id: Map.get(manifest, :id),
      epoch: Map.get(manifest, :epoch),
      name: Map.get(manifest, :name),
      component_sha256: Map.get(manifest, :component_sha256),
      kind: Map.get(manifest, :kind),
      world: Map.get(manifest, :world),
      imports: Map.get(manifest, :imports),
      size: Map.get(manifest, :size),
      created_at: Map.get(manifest, :created_at),
      precompiled: Map.get(manifest, :precompiled),
      metadata: Map.get(manifest, :metadata, %{})
    }

    cond do
      Map.keys(manifest) -- @manifest_keys != [] ->
        {:error, {:unknown_manifest_keys, describe(Map.keys(manifest) -- @manifest_keys)}}

      # W15. `:safe` refuses to *create* an atom and will hand back any atom this VM already
      # interned, so the fixed point below would happily reconstruct a manifest whose `kind` is
      # `:admin` or `:erlang`. The kind decides which of the helper's two worlds these bytes
      # are offered as, so it is held to the closed set here, before anything reads it.
      not Artifact.kind?(Map.get(manifest, :kind)) ->
        {:error, {:invalid_component_kind, describe(Map.get(manifest, :kind))}}

      # W8, for the same reason. The block decides whether this node will `Component::deserialize`
      # somebody else's machine code, and it arrives from a file: held to its shape here, before
      # anything downstream reads a version string out of it.
      not Artifact.precompiled?(Map.get(manifest, :precompiled)) ->
        {:error, {:invalid_precompiled, describe(Map.get(manifest, :precompiled))}}

      Artifact.manifest(artifact) != manifest ->
        {:error, :manifest_not_reconstructible}

      true ->
        {:ok, artifact}
    end
  rescue
    _error -> {:error, :manifest_not_reconstructible}
  end

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
