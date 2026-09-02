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
  defstruct @enforce_keys ++ [metadata: %{}, signature: nil]

  @metadata_keys [:author, :source_sha256, :language, :test_report, :eval, :start]
  @sha256_hex 64
  @signature_bytes 64

  @type signature :: %{signer: String.t(), value: binary()}
  @type t :: %__MODULE__{
          id: String.t(),
          epoch: pos_integer(),
          name: String.t(),
          component_sha256: String.t(),
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
  `metadata.author`) are required. `:id` defaults to a generated one, `:world` to
  `Ouroboros.Wasm.world/0`, and `:imports` to `[]`. The metadata keys
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
    world = Map.get_lazy(attrs, :world, &Wasm.world/0)
    imports = Map.get(attrs, :imports, [])
    name = Map.get(attrs, :name)

    with :ok <- validate_bytes(bytes),
         :ok <- validate_id(id),
         :ok <- validate_epoch(epoch),
         :ok <- validate_name(name),
         :ok <- validate_world(world),
         :ok <- validate_imports(imports),
         :ok <- validate_metadata(metadata) do
      {:ok,
       %__MODULE__{
         id: id,
         epoch: epoch,
         name: name,
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

  defp validate_id(id) when is_binary(id) and id != "", do: :ok
  defp validate_id(id), do: {:error, {:invalid_artifact_id, describe(id)}}

  defp validate_epoch(:missing), do: {:error, {:missing_attribute, :epoch}}
  defp validate_epoch(epoch) when is_integer(epoch) and epoch > 0, do: :ok
  defp validate_epoch(epoch), do: {:error, {:invalid_epoch, describe(epoch)}}

  defp validate_name(name) when is_binary(name) and name != "", do: :ok
  defp validate_name(name), do: {:error, {:invalid_component_name, describe(name)}}

  defp validate_world(world) when is_binary(world) and world != "", do: :ok
  defp validate_world(world), do: {:error, {:invalid_world, describe(world)}}

  defp validate_imports(imports) when is_list(imports) do
    if Enum.all?(imports, &(is_binary(&1) and &1 != "")),
      do: :ok,
      else: {:error, {:invalid_imports, describe(imports)}}
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
