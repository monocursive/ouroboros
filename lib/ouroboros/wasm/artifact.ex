defmodule Ouroboros.Wasm.Artifact do
  @moduledoc """
  A signed manifest describing one WebAssembly component. The bytes travel beside it.

  This is lane W's answer to `Ouroboros.Upgrade.Artifact`, and the shape of the difference
  is the shape of the lane (docs/WASM.md §7.5, D2). A BEAM artifact *contains* the modules
  it deploys, stamped with the OTP/Elixir/architecture triple that decides which nodes may
  load them. A component is one artifact for every node, forever, so there is no triple
  here — and the bytes are not in the struct, because they are already content-addressed
  and already durable in `Ouroboros.Wasm.Store` (§7.4, D6). What is signed is the
  *manifest*: this component's sha256, its size, the world it claims, the imports it
  declares, and its provenance. The bytes are handed to the signer beside the manifest so
  the signer can recompute the sha and the size rather than believe them, and to the
  loading node beside the manifest so it can do the same before staging anything.

  ## The payload tag is different on purpose

      :erlang.term_to_binary({:ouroboros_wasm_v1, signer, manifest}, [:deterministic])

  `Ouroboros.Upgrade.Artifact.signing_payload/2` uses `:ouroboros_upgrade_v1`. Two lanes
  sharing one signer and one trusted-key set must not share a payload space: a signature
  issued over a BEAM artifact could otherwise be replayed as a signature over a component
  whose manifest happened to serialize to the same bytes, and the cheapest way to make
  that impossible is for the two payload spaces to be disjoint by construction.

  ## What `build/2` refuses to be told

  `component_sha256` and `size` are computed **from the bytes**, never read from `attrs`.
  Everything a caller supplies that could name a different component than the one it
  handed over is therefore not a claim this struct can carry. The rest — the id, the name,
  the world, the declared imports, the provenance metadata — *is* a claim, which is why
  `Ouroboros.Upgrade.Signing.Policy.Default` recomputes what it can and refuses what it
  cannot check (§7.5).

  ## Metadata

  `author` is required; a component with no author has no provenance to sign. Optional:
  `source_sha256`, `language`, `test_report`, `eval`, and `start`.

    * `eval` is an `Ouroboros.Upgrade.Rollout.Evaluation` spec, and lane W's signer
      requires one by default (D12): there is no BuildPeer/ExUnit analogue here, so the
      signed eval spec *is* the test story.
    * `start` is `%{id: binary, config: binary}` and is what makes a lane-W capability
      survive a reboot — `Ouroboros.Wasm.Rollout` starts the durable wrapper agent under
      that id when the rollout reaches `:live`, and the boot-time restart starts it again
      from the persisted manifest. It is part of the signed manifest because "this
      capability runs continuously under this id" is a claim a signature should cover.
      The id is not free: it is exactly `"wasm/" <> name`, so a manifest cannot claim a
      durable id belonging to a component other than the one it describes. See
      `Ouroboros.Upgrade.Signing.Policy.Default` and `Ouroboros.Wasm.Rollout.start_block/1`,
      which re-derives it rather than reading it.

  ## `kind`: what these bytes are, signed (W15, contract C7)

  `kind` is `:capability` or `:policy`, and it is in the manifest because it decides which of
  the helper's two worlds these bytes are ever admitted to. A capability answers messages from
  the mesh and from the `capability` tool; a policy answers permission requests for
  `Ouroboros.Wasm.PolicyEngine` and is reachable from neither. The default is `:capability`,
  which is what every manifest written before there were two kinds means.

  It is **signed** rather than configured at deploy for one reason: it is the difference
  between a component a model can send strings to and a component that decides whether the
  model may run `rm`, and a field an operator supplies at deploy time is a field a mistake at
  deploy time can change. The world follows from it — `Ouroboros.Wasm.world_for/1` — so a
  manifest cannot claim one kind and the other kind's world, and the loading node hands the
  helper the kind at `load`, where a component that is not in that world is refused.

  ## The name is narrow, and `imports` holds no duplicates

  `name?/1` is the charset, and it is small because the name is load-bearing: it is the
  rollout register's `module` field and the durable id above. `imports` is refused when it
  repeats an entry, because the helper's own reading of a component is cross-checked
  against this list and a repeated import can never match it — signing one would be
  signing a manifest into a permanent quarantine.
  """

  alias Ouroboros.Wasm

  @enforce_keys [
    :id,
    :epoch,
    :name,
    :component_sha256,
    :world,
    :imports,
    :size,
    :created_at
  ]
  defstruct @enforce_keys ++ [kind: :capability, metadata: %{}, signature: nil]

  @metadata_keys [:author, :source_sha256, :language, :test_report, :eval, :start]
  @sha256_hex 64
  @signature_bytes 64

  # What a WebAssembly binary starts with, and the only thing about the bytes this struct
  # reads besides their digest and their length.
  #
  # It is not a parser and must not become one: §7.3's structural pass and wasmtime's own
  # validator live in the helper, behind W7's bounds, on the node that is about to *run*
  # the component — and `Ouroboros.Upgrade.Signing.Policy.Default` deliberately does not
  # need a helper to decide (D5). What this catches is the case that made a signature
  # meaningless rather than merely wrong: a signer will otherwise happily sign a manifest
  # over a text file, a tarball, or an ELF binary, because every check it makes is about
  # numbers computed *from* those bytes rather than about the bytes being a component at
  # all. Eight bytes of preamble is the cheapest possible "this is at least the right kind
  # of file", and it costs no parse.
  #
  # Both known preambles are accepted: `01 00 00 00` is a core module and `0d 00 01 00` is
  # a component (version 13, layer 1). A core module is not something this lane can run —
  # the helper refuses it against the world — but that refusal belongs where the linker is,
  # and narrowing it here would mean this module claiming to know a binary format it
  # deliberately does not read.
  @wasm_magic "\0asm"
  @wasm_preambles [<<0x01, 0x00, 0x00, 0x00>>, <<0x0D, 0x00, 0x01, 0x00>>]

  # A component's name is not decoration: it is the register's `module` field
  # (`"wasm/" <> name`) and the durable mesh id a `start` block may claim, and both of those
  # are compared as strings by things that trust them. So the charset is the one a name can
  # be *compared* in without surprises — no path separators, no whitespace, no bidirectional
  # controls, nothing outside printable ASCII — and it is bounded, because the id derived
  # from it is bounded too.
  @name_pattern ~r/\A[a-z0-9][a-z0-9._\-]{0,63}\z/
  @max_name_bytes 64

  @type kind :: :capability | :policy
  @type signature :: %{signer: String.t(), value: binary()}
  @type t :: %__MODULE__{
          id: String.t(),
          epoch: pos_integer(),
          name: String.t(),
          component_sha256: String.t(),
          kind: kind(),
          world: String.t(),
          imports: [String.t()],
          size: pos_integer(),
          created_at: String.t(),
          metadata: map(),
          signature: signature() | nil
        }

  @doc """
  Builds a manifest for `bytes`, computing the digest and the size from them.

  `attrs` is a map or keyword list. `:name`, `:epoch`, and `:author` (or
  `metadata.author`) are required. `:id` defaults to a generated one, `:kind` to
  `:capability`, `:world` to the world that kind requires
  (`Ouroboros.Wasm.world_for/1`), and `:imports` to `[]`. The metadata keys
  `#{inspect(@metadata_keys)}` may be given at the top level or inside an explicit
  `:metadata` map; the top-level form wins.

  ## Why the epoch has no default

  `Ouroboros.Upgrade.Artifact.build/2` defaults it to `System.unique_integer/1`, which is
  harmless there because lane B's monotonicity is enforced per node against what that node
  committed. Lane W's is enforced against `Ouroboros.Upgrade.Rollout.Registry`, and
  `Ouroboros.Upgrade.Epoch.next/2` — which allocates the real numbers — never reads that
  register. So one artifact built with a VM-local counter, whose value is unrelated to and
  typically far above any allocated epoch, would raise the register's watermark past every
  epoch `Epoch.next/2` will mint for a long time, and every subsequent deploy would be
  `{:stale_epoch, _, _}`. Recovering means hand-minting above the poisoned number *and*
  re-signing. A default that can do that is not a convenience.

  Allocate it first, the way `Ouroboros.Upgrade.Forge` does:

      {:ok, epoch} = Ouroboros.Upgrade.Epoch.next(nodes)
      {:ok, artifact} = Ouroboros.Wasm.Artifact.build(bytes, name: "greeter", epoch: epoch, ...)
  """
  @spec build(binary(), map() | keyword()) :: {:ok, t()} | {:error, term()}
  def build(bytes, attrs \\ %{})

  def build(bytes, attrs) when is_binary(bytes) and (is_map(attrs) or is_list(attrs)) do
    attrs = normalize(attrs)
    metadata = metadata(attrs)

    epoch = Map.get(attrs, :epoch, :missing)
    id = Map.get_lazy(attrs, :id, &Jido.Signal.ID.generate!/0)
    kind = Map.get(attrs, :kind, :capability)
    # The world follows the kind rather than being defaulted beside it, so a caller that names
    # one and not the other cannot produce a manifest whose two halves disagree. A caller that
    # names both is taken at its word here and refused by the signer, which is the layer that
    # decides whether a world is one this fleet signs for.
    world = Map.get_lazy(attrs, :world, fn -> Wasm.world_for(kind) end)
    imports = Map.get(attrs, :imports, [])
    name = Map.get(attrs, :name)

    with :ok <- validate_bytes(bytes),
         :ok <- validate_preamble(bytes),
         :ok <- validate_id(id),
         :ok <- validate_epoch(epoch),
         :ok <- validate_name(name),
         :ok <- validate_kind(kind),
         :ok <- validate_world(world),
         :ok <- validate_imports(imports),
         :ok <- validate_metadata(metadata) do
      {:ok,
       %__MODULE__{
         id: id,
         epoch: epoch,
         name: name,
         kind: kind,
         # Never `attrs`: the digest and the size are facts about the bytes in hand, and a
         # manifest that took a caller's word for either would be signing a component
         # nobody looked at.
         component_sha256: digest(bytes),
         world: world,
         imports: imports,
         size: byte_size(bytes),
         created_at: DateTime.utc_now() |> DateTime.to_iso8601(),
         metadata: metadata
       }}
    end
  end

  def build(bytes, _attrs) when not is_binary(bytes), do: {:error, {:invalid_component, :bytes}}
  def build(_bytes, attrs), do: {:error, {:invalid_attributes, describe(attrs)}}

  @doc "The signed half of an artifact: everything except the signature envelope."
  @spec manifest(t()) :: map()
  def manifest(%__MODULE__{} = artifact) do
    %{
      id: artifact.id,
      epoch: artifact.epoch,
      name: artifact.name,
      component_sha256: artifact.component_sha256,
      kind: artifact.kind,
      world: artifact.world,
      imports: artifact.imports,
      size: artifact.size,
      created_at: artifact.created_at,
      metadata: artifact.metadata
    }
  end

  @doc """
  The exact bytes a signature over this manifest covers.

  The tag is `:ouroboros_wasm_v1` and not the BEAM lane's `:ouroboros_upgrade_v1`, so a
  signature can never be replayed across lanes. See the moduledoc.
  """
  @spec signing_payload(t(), String.t()) :: binary()
  def signing_payload(%__MODULE__{} = artifact, signer) when is_binary(signer) do
    :erlang.term_to_binary({:ouroboros_wasm_v1, signer, manifest(artifact)}, [:deterministic])
  end

  @doc "Whether this artifact carries a well-formed signature envelope."
  @spec signed?(term()) :: boolean()
  def signed?(%__MODULE__{signature: %{signer: signer, value: value}}) do
    is_binary(signer) and signer != "" and is_binary(value) and
      byte_size(value) == @signature_bytes
  end

  def signed?(_artifact), do: false

  @doc """
  Attaches a signature envelope, refusing one this build could never verify.

  The envelope is checked for shape here rather than at every reader: a 63-byte value or
  an empty signer id is a mistake worth catching where it is made, not a refusal to
  rediscover on each loading node.
  """
  @spec with_signature(t(), signature()) :: {:ok, t()} | {:error, term()}
  def with_signature(%__MODULE__{} = artifact, %{signer: signer, value: value})
      when is_binary(signer) and is_binary(value) do
    cond do
      signer == "" ->
        {:error, :invalid_signer}

      byte_size(value) != @signature_bytes ->
        {:error, {:invalid_signature, signer}}

      # Rebuilt rather than kept: an envelope carrying anything besides these two keys is
      # narrowed to the two, so no reader downstream has to wonder what else was in it.
      true ->
        {:ok, %{artifact | signature: %{signer: signer, value: value}}}
    end
  end

  def with_signature(%__MODULE__{}, signature),
    do: {:error, {:invalid_signature_envelope, describe(signature)}}

  def with_signature(artifact, _signature), do: {:error, {:invalid_artifact, describe(artifact)}}

  @doc "The lower-case hex sha256 of `bytes`, the one identity a lane-W capability has."
  @spec digest(binary()) :: String.t()
  def digest(bytes) when is_binary(bytes),
    do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  @doc """
  Whether `value` is a name a component may be deployed under.

  Lower case, starting with a letter or a digit, then letters, digits, `.`, `_` and `-`,
  at most #{@max_name_bytes} bytes. Narrow on purpose: this name *is* the rollout
  register's `module` field (`"wasm/" <> name`) and the durable mesh id a signed `start`
  block claims cluster-wide, so anything a reader could confuse with a path segment, a
  different name under a Unicode normalization, or a name reversed by a bidirectional
  control is not a name this lane will sign.
  """
  @spec name?(term()) :: boolean()
  def name?(value) when is_binary(value),
    do: byte_size(value) <= @max_name_bytes and Regex.match?(@name_pattern, value)

  def name?(_value), do: false

  @doc """
  Whether `value` is one of the two kinds a lane-W component may be (W15).

  A closed set of two atoms, checked rather than pattern-matched at each reader, because the
  kind arrives from a manifest a bundle carried and `:erlang.binary_to_term/2`'s `:safe` refuses
  only to *create* atoms — it will happily hand back any atom this VM already interned.
  """
  @spec kind?(term()) :: boolean()
  def kind?(value), do: value in Wasm.kinds()

  @doc "Whether `value` is the 64-character lower-case hex a component sha is written as."
  @spec sha256?(term()) :: boolean()
  def sha256?(value) when is_binary(value),
    do: byte_size(value) == @sha256_hex and value =~ ~r/\A[0-9a-f]{#{@sha256_hex}}\z/

  def sha256?(_value), do: false

  defp normalize(attrs) when is_map(attrs), do: attrs
  defp normalize(attrs) when is_list(attrs), do: Map.new(attrs)

  # Top level wins over an explicit `:metadata` map, so a caller that passes both is not
  # left guessing which author was signed.
  defp metadata(attrs) do
    base = Map.get(attrs, :metadata, %{})

    if is_map(base) and not is_struct(base) do
      Map.merge(base, Map.take(attrs, @metadata_keys))
    else
      base
    end
  end

  defp validate_bytes(""), do: {:error, :empty_component}
  defp validate_bytes(_bytes), do: :ok

  # Eight bytes, no parse. See the attribute above for what this does and does not claim.
  defp validate_preamble(<<@wasm_magic, preamble::binary-size(4), _rest::binary>>) do
    if preamble in @wasm_preambles,
      do: :ok,
      else: {:error, {:not_a_wasm_binary, :preamble, Base.encode16(preamble, case: :lower)}}
  end

  defp validate_preamble(_bytes), do: {:error, {:not_a_wasm_binary, :magic}}

  defp validate_id(id) when is_binary(id) and id != "", do: :ok
  defp validate_id(id), do: {:error, {:invalid_artifact_id, describe(id)}}

  defp validate_epoch(:missing), do: {:error, {:missing_attribute, :epoch}}
  defp validate_epoch(epoch) when is_integer(epoch) and epoch > 0, do: :ok
  defp validate_epoch(epoch), do: {:error, {:invalid_epoch, describe(epoch)}}

  defp validate_name(name) do
    if name?(name), do: :ok, else: {:error, {:invalid_component_name, describe(name)}}
  end

  defp validate_kind(kind) do
    if kind?(kind), do: :ok, else: {:error, {:invalid_component_kind, describe(kind)}}
  end

  defp validate_world(world) when is_binary(world) and world != "", do: :ok
  defp validate_world(world), do: {:error, {:invalid_world, describe(world)}}

  # Duplicates are refused here as well as at the signer: `Ouroboros.Wasm.Verifier`
  # cross-checks the helper's sorted import list against this one, and a list holding
  # `"log"` twice can never equal a helper's reading of the same component.
  defp validate_imports(imports) when is_list(imports) do
    cond do
      not Enum.all?(imports, &(is_binary(&1) and &1 != "")) ->
        {:error, {:invalid_imports, describe(imports)}}

      Enum.uniq(imports) != imports ->
        {:error, {:duplicate_imports, describe(imports)}}

      true ->
        :ok
    end
  end

  defp validate_imports(imports), do: {:error, {:invalid_imports, describe(imports)}}

  defp validate_metadata(metadata) when is_map(metadata) and not is_struct(metadata) do
    case Map.get(metadata, :author) do
      author when is_binary(author) and author != "" -> :ok
      _absent -> {:error, {:invalid_metadata, :author}}
    end
  end

  defp validate_metadata(metadata), do: {:error, {:invalid_metadata, describe(metadata)}}

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
