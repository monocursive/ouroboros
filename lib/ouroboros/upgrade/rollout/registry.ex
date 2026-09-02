defmodule Ouroboros.Upgrade.Rollout.Registry do
  @moduledoc """
  The durable deployment-level record of every capability this cluster has forged.

  Node executors journal what one node did. This registry journals what the *rollout*
  intended and what became of it, on the node that drove it. It is written before the
  mutation it describes, in the same order every other store in this codebase uses: the
  `:deploying` checkpoint is durable before `Coordinator.deploy/3` is called, so a forge
  that dies mid-rollout leaves evidence that a rollout was in flight instead of leaving a
  capability nobody remembers deploying.

  Five states, and the difference between rollback and quarantine is the whole point:

    * `:deploying` - checkpointed, outcome not yet known. A `:deploying` entry found at
      startup means a rollout was interrupted and its nodes must be inspected.
    * `:live` - committed and health-checked on every target, and still the version this
      plane believes is running there.
    * `:superseded` - was live, then a later compare-replace of the same module on
      overlapping nodes reached `:live`. Finished history, not current inventory.
    * `:rolled_back` - every target proved it compensated. Only proof earns this state.
    * `:quarantined` - the outcome is ambiguous somewhere. A node that never answered
      may be running the code; saying "rolled back" here would be a claim nobody made.

  A quarantined entry has no automatic exit. Clearing it means reconciling the nodes
  themselves through `NodeExecutor.reconcile_quarantine/1` and deciding, as an operator,
  what the cluster is actually running.

  Storage comes from `config :ouroboros, :capability_storage`: ETS in dev and test, a
  synced `Ouroboros.Storage.DurableFile` in production. As with every other store here,
  ETS means the record dies with the VM, and the durability level is reported rather
  than assumed.

  A rollout names a module the forge compiled at runtime, so the checkpoint carries that
  name as a binary and `Ouroboros.Upgrade.ModuleName` resolves it back on read. A
  registry that journaled the atom could not be read back at all by the rebooted VM
  that has to read it; an entry whose name no longer resolves keeps the binary, because
  "this node has not loaded that module" is a true thing to record about a rollout that
  happened before the reboot.

  ## Two lanes in one register

  A lane-W rollout deploys a WebAssembly component and introduces no module and no atom
  at all (docs/WASM.md D2), so its `module` is the binary `"wasm/" <> name` and its
  `component_sha256` is the identity that actually decides what runs. That is the only
  binary form this register accepts **from a caller**: a name that is neither a module atom
  nor a lane-W component is still `{:invalid_attribute, :module, _}` at `deploying/2`,
  because "binary-tolerant" was always about names crossing a checkpoint, never about
  admitting anything at all. Reading a checkpoint is the other side of exactly that
  sentence and is looser by exactly that much — see below.

  Keeping both lanes here rather than forking a second register is D7. The states, the
  transition table, the supersede rule, the pruning rule and the ambiguity discipline are
  identical for both — only the thing being deployed differs — and a second copy of them
  would be a second place for the rule "ambiguity is never a rollback" to drift.

  ## `eval_report`, `component_sha256`, and the checkpoint versions that carry them

  An entry also holds whatever `Ouroboros.Upgrade.Rollout.Evaluation` proved on the way
  to this state: counts, timings, and the first few failures per node, never full probe
  transcripts. A rollout record that grew with the size of the specs it ran would be a
  durable store nobody can bound, so an oversized or unportable report is replaced by a
  marker saying so rather than truncated into something that reads like evidence.

  Those two fields are why the checkpoint is version 3. Version 1 knew neither; version 2
  knew `eval_report`. Both are *upgraded* on read by the same widening: every entry keeps
  every field it recorded and gains the ones it never had as `nil`, which is the truth
  about them — those rollouts were never evaluated, and those rollouts named no component.
  A newer checkpoint is still refused rather than coerced, the way the node executor's
  journal refuses a shape it cannot interpret, because a field this build would silently
  drop is not a field it may rewrite.

  `test_report`, `detail` and `eval_report` are all held to the same bound on the way in.
  The first two arrive from a signed manifest and from a settling rollout, which means a
  requester chooses them, and an unbounded durable store is not one — see `bound_report/2`.

  ## What a checkpoint is re-validated against on read, and what happens to one bad entry

  Every entry is held to the validators `deploying/2` applies, again, on load: the id is a
  binary and matches the entry's own `artifact_id`, the epoch is a positive integer *no
  larger than a number this cluster could have minted*, the sha is 64 lower-case hex or
  `nil`, the state is one of the five, `nodes` is non-empty, and the timestamps are
  strings. What is *looser* on read than on write is the two names that
  cross a reboot: a module and a node name this VM never interned come back as binaries,
  and both kinds are accepted, because that is what a rollout of code this node no longer
  holds looks like from here.

  An entry that fails is **dropped with a logged reason and the rest of the register
  loads**. Refusing the whole checkpoint for one row meant a single planted or unreadable
  entry made the node unable to deploy anything, forever — the failure mode the epoch
  watermark had, below. Two shapes are worth naming: a rollout id that spelled an atom
  (`"nil"`, `"error"`) in a checkpoint written before map keys were tagged came back as
  that atom and is **migrated** to its string rather than dropped, because the entry beside
  it still records the id and the two agree; anything else that is not a usable key is
  dropped.

  ## The epoch watermark is a high-water mark, and it is durable

  `lane_w_epoch` is carried in the checkpoint. Deriving the watermark from the surviving
  entries alone let `prune/2` lower it: the entry at the highest epoch is settled history,
  which is the first thing pruning discards, and its number was free again the moment it
  went. The mark only rises, the entries are folded in on top of it, and the field is
  additive — a checkpoint that has never held one reads as `0`, and an older build that
  drops it falls back to deriving, which is where the number came from.

  ## What the epoch ceiling holds, and what it does not

  `Ouroboros.Upgrade.Epoch` is a counter: one number per allocation, from zero. A number
  above 10^14 was therefore not minted by this cluster — reaching it
  takes a hundred trillion deploys — so an *entry* carrying one is dropped like any other
  unreadable entry, and a *watermark* carrying one is ignored with a warning and the mark
  falls back to the entries. The same ceiling applies at `deploying/2`, so a caller cannot
  write a number this build would refuse to read back.

  Be exact about what that buys, because it is narrower than it looks. It closes the two
  **unrecoverable** shapes: an epoch so high no future allocation can exceed it, and a
  watermark with no entry behind it to delete — the one that survived pruning every row and
  left an operator nothing to remove. It does **not** make a tampered checkpoint safe. A
  planted entry at a merely large but plausible epoch (10^9, say) still refuses every deploy
  below it; what recovers from that is deleting the entry, which now works again because
  the watermark cannot be poisoned above the ceiling in its place. And nothing here defends
  a node whose checkpoint file an attacker can write at all — that node is already lost.
  What the ceiling makes true is that the damage stays *recoverable by an operator*.

  `component_sha256` is a lower-case 64-hex **string** end to end: in the struct, across
  the checkpoint, and back. Nothing interns it, nothing resolves it, and
  `Ouroboros.Wasm.Store.protected_shas/1` reads it to decide which component bytes a prune
  may never evict (§7.4).

  ## Lane W's epoch gates live here, and they are atomic

  An epoch is the replay defence: an old artifact re-presented later is refused for its
  number, whatever its bytes say. Lane B enforces that per node, inside
  `Ouroboros.Upgrade.NodeExecutor.handle_call({:prepare, ...})`, where the check and the
  record it is checked against are the same serialized message. Lane W has no node
  executor, so every node's register is where its monotonicity lives. The driver spends the
  epoch inside `deploying/2`; each target spends it inside `admit_wasm_epoch/2` before staging
  bytes. Both decisions live in a serialized `handle_call`, for exactly the reason the node
  executor's does. A caller reading the highest epoch and then checkpointing would be a
  read-then-write across two messages, and two concurrent deploys at epochs 70 and 60
  would both pass their reads and both checkpoint.

  So: a `:deploying` request that carries a `component_sha256`, or a target admission, is refused
  `{:stale_epoch, epoch, highest}` unless its epoch is strictly greater than every lane-W
  entry this register holds, **in any state**. Any state, because a `:deploying` entry may
  yet become live, a `:quarantined` one may be running right now, and a `:rolled_back` one
  is a number that was already spent. Lane B entries are not looked at and lane B requests
  are not checked: nothing about this rule changes what a BEAM rollout may record.
  """

  use GenServer

  require Logger

  alias Ouroboros.Upgrade.{Beam, ModuleName, Wire}

  @store_key {:ouroboros, :capability_rollouts, 1}
  @checkpoint_version 3
  @upgradable_versions [1, 2]
  @states [:deploying, :live, :superseded, :rolled_back, :quarantined]
  @default_limit 200
  @max_eval_report_bytes 32_768

  # The largest epoch a number this cluster minted could plausibly be. `Ouroboros.Upgrade.Epoch`
  # is a *counter*: `next/2` allocates `max(what the nodes report, the durable watermark) + 1`,
  # starting from zero, one number per allocation. Reaching 10^14 therefore takes a hundred
  # trillion deploys — a thousand a second, without pause, for three thousand years. It is
  # also comfortably above a hand-minted number taken from a millisecond clock, which is
  # around 1.8 x 10^12 today and does not reach this until the year 5138.
  #
  # So a bigger number was not minted here, and the two places it could arrive from are the
  # two places it is refused: an entry read back from a checkpoint, and the checkpoint's own
  # watermark field. See the moduledoc for what this does and does not buy.
  @max_plausible_epoch 100_000_000_000_000

  # The one binary form `module` accepts. See the moduledoc: binary-tolerance is about
  # names crossing a checkpoint, not about admitting arbitrary strings as capabilities.
  @wasm_prefix "wasm/"
  @sha256_hex 64

  @transitions %{
    deploying: [:live, :rolled_back, :quarantined],
    live: [:rolled_back, :quarantined, :superseded],
    superseded: [:quarantined],
    rolled_back: [:quarantined],
    quarantined: []
  }

  defmodule Entry do
    @moduledoc "One capability rollout and everything known about its outcome."

    @enforce_keys [:artifact_id, :module, :epoch, :nodes, :state, :created_at, :updated_at]

    defstruct @enforce_keys ++
                [
                  source_sha256: nil,
                  component_sha256: nil,
                  test_report: %{},
                  detail: nil,
                  eval_report: nil
                ]

    @type state :: :deploying | :live | :superseded | :rolled_back | :quarantined
    @type t :: %__MODULE__{
            artifact_id: String.t(),
            # A name read back from a checkpoint stays a binary when this VM has never
            # interned it, which is what a rollout of code this node no longer holds
            # looks like from here. A lane-W rollout's name is a binary from the start:
            # `"wasm/" <> name`, for a deployment that introduces no atom at all.
            module: module() | String.t(),
            epoch: pos_integer(),
            nodes: [node()],
            state: state(),
            source_sha256: String.t() | nil,
            # Lane W's real identity: the sha256 of the component bytes, lower-case hex.
            # `nil` for lane B, which deploys modules and not components.
            component_sha256: String.t() | nil,
            test_report: map(),
            detail: term(),
            eval_report: map() | nil,
            created_at: String.t(),
            updated_at: String.t()
          }
  end

  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Checkpoints the intent to deploy a capability, before anything is mutated.

  Requires `:artifact_id`, `:module`, `:epoch`, and `:nodes`; accepts `:source_sha256`,
  `:component_sha256`, and `:test_report`.

  A request carrying `:component_sha256` is a lane-W rollout and is also held to this
  register's epoch watermark — `{:stale_epoch, epoch, highest}` — in the same serialized
  call that records it. See the moduledoc for why the check is here and not at the caller.
  """
  @spec deploying(keyword() | map(), GenServer.server()) :: {:ok, Entry.t()} | {:error, term()}
  def deploying(attrs, server \\ __MODULE__) do
    GenServer.call(server, {:deploying, Map.new(attrs)})
  end

  @doc """
  Atomically spends a lane-W epoch on the node that is about to stage the component.

  The same artifact may repeat the claim, which makes a retry after an ambiguous transport
  result safe. Any different artifact at that epoch, or any lower epoch, is stale. This is
  the target-local half of `deploying/2`'s driver-side checkpoint: without it, moving the
  driver to another core also moved the only replay defence.
  """
  @spec admit_wasm_epoch(keyword() | map(), GenServer.server()) :: :ok | {:error, term()}
  def admit_wasm_epoch(attrs, server \\ __MODULE__) do
    GenServer.call(server, {:admit_wasm_epoch, Map.new(attrs)})
  end

  @doc """
  Moves a rollout to a new state, refusing transitions that would lose information.

  `:detail` records the evidence for the transition. `:eval_report` records what an
  evaluation gate proved on the way to it; omitting it keeps whatever the entry already
  held, so marking an entry twice cannot erase the report that justified the first mark.
  """
  @spec mark(String.t(), Entry.state(), keyword(), GenServer.server()) ::
          {:ok, Entry.t()} | {:error, term()}
  def mark(artifact_id, state, opts \\ [], server \\ __MODULE__)
      when is_binary(artifact_id) and is_atom(state) and is_list(opts) do
    GenServer.call(
      server,
      {:mark, artifact_id, state, Keyword.get(opts, :detail), Keyword.get(opts, :eval_report)}
    )
  end

  @spec get(String.t(), GenServer.server()) :: {:ok, Entry.t()} | :not_found
  def get(artifact_id, server \\ __MODULE__) when is_binary(artifact_id) do
    GenServer.call(server, {:get, artifact_id})
  end

  @spec list(GenServer.server()) :: [Entry.t()]
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @doc """
  Returns every rollout for one capability, oldest first.

  Takes either form of a name: a module atom, or the `"wasm/" <> name` a lane-W rollout
  records. `same_module?/2` compares them across the checkpoint boundary, so a caller does
  not have to know which side of a reboot it is on.
  """
  @spec history(module() | String.t(), GenServer.server()) :: [Entry.t()]
  def history(module, server \\ __MODULE__) when is_atom(module) or is_binary(module) do
    server |> list() |> Enum.filter(&same_module?(&1.module, module))
  end

  @doc "Returns the rollouts currently believed to be live."
  @spec live(GenServer.server()) :: [Entry.t()]
  def live(server \\ __MODULE__), do: server |> list() |> Enum.filter(&(&1.state == :live))

  @type durability :: :ephemeral_checkpoint | :durable_checkpoint | :synced_checkpoint

  @spec durability(GenServer.server()) :: durability()
  def durability(server \\ __MODULE__), do: GenServer.call(server, :durability)

  @doc "The highest lane-W epoch this node has admitted, including target-only claims."
  @spec wasm_epoch(GenServer.server()) :: non_neg_integer()
  def wasm_epoch(server \\ __MODULE__), do: GenServer.call(server, :wasm_epoch)

  @doc false
  def checkpoint_key, do: @store_key

  @impl true
  def init(opts) do
    with {:ok, storage} <- storage_config(opts),
         {:ok, adapter, adapter_opts} <- normalize_storage(storage),
         {:ok, rollouts, watermark, claim} <- load(adapter, adapter_opts) do
      {:ok,
       %{
         adapter: adapter,
         opts: adapter_opts,
         rollouts: rollouts,
         lane_w_epoch: watermark,
         lane_w_claim: claim,
         limit: limit(opts),
         durability: durability_level(adapter)
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:deploying, attrs}, _from, state) do
    with {:ok, entry} <- build_entry(attrs),
         :ok <- ensure_absent(state, entry.artifact_id),
         :ok <- ensure_fresh_epoch(state, entry) do
      persist(entry, state)
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:admit_wasm_epoch, attrs}, _from, state) do
    with {:ok, claim} <- build_epoch_claim(attrs),
         :ok <- ensure_claimable(state, claim) do
      persist_epoch_claim(claim, state)
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:mark, artifact_id, next, detail, eval_report}, _from, state) do
    with {:ok, entry} <- fetch(state, artifact_id),
         :ok <- ensure_transition(entry.state, next) do
      persist(
        %{
          entry
          | state: next,
            detail: bound_report(detail, :detail),
            eval_report: bound_report(eval_report) || entry.eval_report,
            updated_at: now()
        },
        state
      )
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:get, artifact_id}, _from, state) do
    case fetch(state, artifact_id) do
      {:ok, entry} -> {:reply, {:ok, entry}, state}
      {:error, _reason} -> {:reply, :not_found, state}
    end
  end

  def handle_call(:list, _from, state) do
    {:reply, state.rollouts |> Map.values() |> Enum.sort_by(& &1.created_at), state}
  end

  def handle_call(:durability, _from, state), do: {:reply, state.durability, state}
  def handle_call(:wasm_epoch, _from, state), do: {:reply, highest_lane_w_epoch(state), state}

  defp build_entry(attrs) do
    with {:ok, artifact_id} <- fetch_binary(attrs, :artifact_id),
         {:ok, module} <- fetch_module(attrs),
         {:ok, epoch} <- fetch_epoch(attrs),
         {:ok, nodes} <- fetch_nodes(attrs),
         {:ok, component_sha256} <- fetch_component_sha256(attrs) do
      timestamp = now()

      {:ok,
       %Entry{
         artifact_id: artifact_id,
         module: module,
         epoch: epoch,
         nodes: nodes,
         state: :deploying,
         source_sha256: Map.get(attrs, :source_sha256),
         component_sha256: component_sha256,
         test_report: bound_report(Map.get(attrs, :test_report, %{}), :test_report) || %{},
         created_at: timestamp,
         updated_at: timestamp
       }}
    end
  end

  defp build_epoch_claim(attrs) do
    with {:ok, artifact_id} <- fetch_binary(attrs, :artifact_id),
         {:ok, epoch} <- fetch_epoch(attrs),
         {:ok, component_sha256} <- fetch_component_sha256(attrs),
         true <- is_binary(component_sha256) do
      {:ok,
       %{
         artifact_id: artifact_id,
         epoch: epoch,
         component_sha256: component_sha256
       }}
    else
      false -> {:error, {:missing_attribute, :component_sha256}}
      {:error, _reason} = error -> error
    end
  end

  # A report is somebody else's summary of somebody else's node, so it is admitted on
  # this store's terms or not at all: portable, and small enough that a bounded registry
  # stays bounded. A rejected report leaves a marker rather than a half-report, because a
  # truncated map still reads like evidence.
  #
  # All three fields a caller can fill go through here, and that is the point. `eval_report`
  # is a gate's summary, `test_report` is a *signed manifest's* provenance, and `detail` is
  # whatever a settling rollout wrote — the last two are chosen by whoever built the
  # manifest, so a 2 MB report or a pid in one of them would be a 2 MB checkpoint file, or a
  # term the next boot's `[:safe]` read cannot make sense of, on somebody else's say-so.
  defp bound_report(report, field \\ :eval_report)

  defp bound_report(nil, _field), do: nil

  defp bound_report(report, field) do
    cond do
      not Beam.portable_term?(report) ->
        %{field => :unportable, rendered: inspect(report, limit: 5, printable_limit: 200)}

      byte_size(:erlang.term_to_binary(report)) > @max_eval_report_bytes ->
        %{field => :too_large, bytes: byte_size(:erlang.term_to_binary(report))}

      true ->
        report
    end
  end

  defp ensure_absent(state, artifact_id) do
    if Map.has_key?(state.rollouts, artifact_id),
      do: {:error, {:already_recorded, artifact_id}},
      else: :ok
  end

  # Lane B is untouched: it has a node executor enforcing this per node, and a BEAM rollout
  # carries no component sha to recognize it by.
  defp ensure_fresh_epoch(_state, %Entry{component_sha256: nil}), do: :ok

  defp ensure_fresh_epoch(state, %Entry{epoch: epoch}) do
    highest = highest_lane_w_epoch(state)

    if epoch > highest, do: :ok, else: {:error, {:stale_epoch, epoch, highest}}
  end

  defp ensure_claimable(state, %{epoch: epoch} = claim) do
    highest = highest_lane_w_epoch(state)

    cond do
      state.lane_w_claim == claim and epoch == highest -> :ok
      epoch > highest -> :ok
      true -> {:error, {:stale_epoch, epoch, highest}}
    end
  end

  # The watermark is the *high-water mark*, not the highest surviving entry. Deriving it
  # from the entries alone made `prune/2` able to lower it: a settled rollout at the
  # highest epoch is exactly the kind of history pruning discards first, and once it was
  # gone its number was free again. So the mark is carried in the checkpoint beside the
  # entries and only ever rises, and what is derived from the entries is folded in on top
  # of it — a planted entry above the mark still counts, and a pruned one no longer has to.
  defp highest_lane_w_epoch(state) do
    max(state.lane_w_epoch, derived_lane_w_epoch(state.rollouts))
  end

  # Every state counts. A `:deploying` entry may yet become live, a `:quarantined` one may
  # be running right now, and a `:rolled_back` one is a number that was already spent — so
  # none of them is a number a later manifest may reuse.
  defp derived_lane_w_epoch(rollouts) do
    rollouts
    |> Map.values()
    |> Enum.filter(&is_binary(Map.get(&1, :component_sha256)))
    |> Enum.map(&Map.get(&1, :epoch))
    |> Enum.filter(&is_integer/1)
    |> Enum.max(fn -> 0 end)
  end

  defp fetch(state, artifact_id) do
    case Map.fetch(state.rollouts, artifact_id) do
      {:ok, entry} -> {:ok, entry}
      :error -> {:error, {:unknown_rollout, artifact_id}}
    end
  end

  defp ensure_transition(from, to) do
    cond do
      to not in @states -> {:error, {:invalid_state, to}}
      to in Map.get(@transitions, from, []) -> :ok
      true -> {:error, {:invalid_transition, from, to}}
    end
  end

  # The effect this registry describes happens after its checkpoint, so a failed write is
  # reported without touching in-memory state: the caller must not proceed.
  defp persist(entry, state) do
    rollouts = state.rollouts |> put_entry(entry) |> prune(state.limit)
    watermark = max(state.lane_w_epoch, derived_lane_w_epoch(rollouts))
    claim = advance_claim(state.lane_w_claim, rollouts)

    case write_checkpoint(state, rollouts, watermark, claim) do
      :ok ->
        {:reply, {:ok, entry},
         %{state | rollouts: rollouts, lane_w_epoch: watermark, lane_w_claim: claim}}

      {:error, {:commit_outcome_unknown, _reason} = ambiguity} ->
        {:stop, ambiguity, {:error, {:rollout_commit_outcome_unknown, ambiguity}}, state}

      {:error, reason} ->
        {:reply, {:error, {:rollout_checkpoint_failed, reason}}, state}

      other ->
        {:reply, {:error, {:invalid_rollout_storage_response, other}}, state}
    end
  end

  defp persist_epoch_claim(claim, %{lane_w_claim: claim} = state),
    do: {:reply, :ok, state}

  defp persist_epoch_claim(claim, state) do
    case write_checkpoint(state, state.rollouts, claim.epoch, claim) do
      :ok ->
        {:reply, :ok, %{state | lane_w_epoch: claim.epoch, lane_w_claim: claim}}

      {:error, {:commit_outcome_unknown, _reason} = ambiguity} ->
        {:stop, ambiguity, {:error, {:rollout_commit_outcome_unknown, ambiguity}}, state}

      {:error, reason} ->
        {:reply, {:error, {:rollout_checkpoint_failed, reason}}, state}

      other ->
        {:reply, {:error, {:invalid_rollout_storage_response, other}}, state}
    end
  end

  # Encoding is inside the rescue, not in the argument list of a call that has one. The
  # checkpoint is built from an entry whose `test_report` and `detail` came from somebody
  # else's manifest, and a `Wire.dump/1` that raised over there raised *here* — outside
  # `adapter_call/3`'s rescue, out of `handle_call/3`, killing the register and every
  # rollout record it was holding. A write this process cannot encode is a refused write,
  # the same as a write the adapter would not take.
  #
  # `Ouroboros.Upgrade.Wire.dump/1` is total now, so nothing reaches this clause: it is the
  # belt, and the brace is that boundary's own promise, swept in `Ouroboros.Upgrade.WireTest`.
  # It stays because the argument-position bug is structural — any future encoder that can
  # raise would kill this GenServer again — and a refusal here costs one rollout while a
  # raise costs the whole register.
  defp write_checkpoint(state, rollouts, watermark, claim) do
    adapter_call(state.adapter, :put_checkpoint, [
      @store_key,
      checkpoint(rollouts, watermark, claim),
      state.opts
    ])
  rescue
    error -> {:error, {:rollout_checkpoint_unencodable, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:rollout_checkpoint_unencodable, {kind, inspect(reason, limit: 5)}}}
  end

  # Marking a module live displaces any overlapping live record of the same module in
  # the same persist. Two `:live` rows for one module would make `live/1` over-report
  # and let a later forge of the old digest claim the work was already done.
  defp put_entry(rollouts, %Entry{state: :live} = live) do
    rollouts
    |> Map.put(live.artifact_id, live)
    |> Map.new(fn
      {id, _entry} when id == live.artifact_id ->
        {id, live}

      {id, %Entry{} = entry} ->
        if entry.state == :live and same_module?(entry.module, live.module) and
             Enum.any?(entry.nodes, &(&1 in live.nodes)) do
          {id,
           %{
             entry
             | state: :superseded,
               detail: %{replaced_by: live.artifact_id},
               updated_at: live.updated_at
           }}
        else
          {id, entry}
        end

      other ->
        other
    end)
  end

  defp put_entry(rollouts, entry), do: Map.put(rollouts, entry.artifact_id, entry)

  # Growth is bounded by dropping the oldest settled history only. A `:deploying`,
  # `:live`, or `:quarantined` entry is unfinished business and is never discarded to make
  # room for history. `:superseded` is finished inventory, same as a proven rollback.
  defp prune(rollouts, limit) when map_size(rollouts) <= limit, do: rollouts

  defp prune(rollouts, limit) do
    droppable =
      rollouts
      |> Map.values()
      |> Enum.filter(&(&1.state in [:rolled_back, :superseded]))
      |> Enum.sort_by(& &1.updated_at)

    Enum.reduce_while(droppable, rollouts, fn entry, acc ->
      if map_size(acc) > limit do
        {:cont, Map.delete(acc, entry.artifact_id)}
      else
        {:halt, acc}
      end
    end)
  end

  # These fields are additive and need no new checkpoint version. The claim makes the
  # highest epoch idempotent for the one artifact that spent it on this target; an older
  # build ignores both fields and falls back to deriving the mark from rollout entries.
  defp checkpoint(rollouts, watermark, claim) do
    Wire.dump(%{
      version: @checkpoint_version,
      rollouts: to_wire(rollouts),
      lane_w_epoch: watermark,
      lane_w_claim: claim
    })
  end

  defp advance_claim(current, rollouts) do
    case derived_claim(rollouts) do
      nil ->
        current

      candidate when is_nil(current) ->
        candidate

      %{epoch: epoch} = candidate when epoch > current.epoch ->
        candidate

      _older_or_equal ->
        current
    end
  end

  defp derived_claim(rollouts) do
    rollouts
    |> Map.values()
    |> Enum.filter(&is_binary(Map.get(&1, :component_sha256)))
    |> Enum.max_by(&Map.get(&1, :epoch, 0), fn -> nil end)
    |> case do
      nil -> nil
      entry -> epoch_claim(entry)
    end
  end

  defp epoch_claim(entry) do
    %{
      artifact_id: Map.get(entry, :artifact_id),
      epoch: Map.get(entry, :epoch),
      component_sha256: Map.get(entry, :component_sha256)
    }
  end

  # Two names for one module compare equal whichever side of the checkpoint boundary
  # each of them came from.
  defp same_module?(left, right), do: ModuleName.to_wire(left) == ModuleName.to_wire(right)

  defp to_wire(rollouts), do: map_modules(rollouts, &ModuleName.to_wire/1)
  defp from_wire(rollouts), do: map_modules(rollouts, &ModuleName.from_wire/1)

  defp map_modules(rollouts, fun) do
    Map.new(rollouts, fn
      {id, %Entry{} = entry} -> {id, %{entry | module: fun.(entry.module)}}
      other -> other
    end)
  end

  defp load(adapter, adapter_opts) do
    case adapter_call(adapter, :get_checkpoint, [@store_key, adapter_opts]) do
      :not_found ->
        {:ok, %{}, 0, nil}

      {:ok, wire} ->
        case Wire.load(wire) do
          %{version: version, rollouts: rollouts} = held when is_map(rollouts) ->
            load_held(version, rollouts, held)

          %{"version" => version, "rollouts" => rollouts} = held when is_map(rollouts) ->
            load_held(version, rollouts, held)

          _invalid ->
            {:error, :invalid_rollout_checkpoint}
        end

      {:error, reason} ->
        {:error, {:rollout_checkpoint_unreadable, reason}}

      other ->
        {:error, {:invalid_rollout_storage_response, other}}
    end
  end

  defp load_held(version, rollouts, held) do
    with {:ok, kept, watermark} <- upgrade(version, from_wire(rollouts), watermark(held)) do
      {:ok, kept, watermark, checkpoint_claim(held, kept, watermark)}
    end
  end

  defp checkpoint_claim(held, rollouts, watermark) do
    case normalize_claim(Map.get(held, :lane_w_claim) || Map.get(held, "lane_w_claim")) do
      %{epoch: ^watermark} = claim -> claim
      _absent_or_invalid -> claim_at(rollouts, watermark)
    end
  end

  defp normalize_claim(claim) when is_map(claim) do
    attrs = %{
      artifact_id: Map.get(claim, :artifact_id) || Map.get(claim, "artifact_id"),
      epoch: Map.get(claim, :epoch) || Map.get(claim, "epoch"),
      component_sha256: Map.get(claim, :component_sha256) || Map.get(claim, "component_sha256")
    }

    case build_epoch_claim(attrs) do
      {:ok, normalized} -> normalized
      {:error, _reason} -> nil
    end
  end

  defp normalize_claim(_absent_or_invalid), do: nil

  defp claim_at(rollouts, watermark) do
    rollouts
    |> Map.values()
    |> Enum.find(
      &(Map.get(&1, :epoch) == watermark and is_binary(Map.get(&1, :component_sha256)))
    )
    |> case do
      nil -> nil
      entry -> epoch_claim(entry)
    end
  end

  # A mark this build does not recognize is `0`, which is the honest reading: this
  # checkpoint records no high-water mark, so the entries are all there is to go on.
  #
  # That fallback is also the answer to an implausible one, and this field needs an answer
  # more than an entry does: an entry can be deleted, and the watermark is the one number
  # with nothing behind it to delete. A checkpoint holding no entries at all and only a
  # planted mark refused every deploy with nothing an operator could remove. So a number no
  # allocation could have reached is ignored rather than enforced, loudly.
  defp watermark(held) do
    case Map.get(held, :lane_w_epoch) || Map.get(held, "lane_w_epoch") do
      value when is_integer(value) and value >= 0 and value <= @max_plausible_epoch ->
        value

      value when is_integer(value) and value > @max_plausible_epoch ->
        Logger.warning(
          "rollout registry ignored an implausible lane-W epoch watermark: " <>
            "#{value} is above #{@max_plausible_epoch}, which no allocation could have reached"
        )

        0

      _absent_or_invalid ->
        0
    end
  end

  defp upgrade(@checkpoint_version, rollouts, watermark), do: accept(rollouts, watermark)

  # Widening an entry is the one migration that loses nothing, and one widening covers
  # every older version: every field an old rollout recorded is kept, and the fields it
  # never had become `nil`. For a version-1 entry that is `eval_report` and
  # `component_sha256`; for a version-2 entry it is `component_sha256` alone. Both `nil`s
  # are the truth — those rollouts were never evaluated, and those rollouts named no
  # component. A newer checkpoint is still refused, because a field this build would
  # silently drop is not a field it may rewrite.
  defp upgrade(version, rollouts, watermark) when version in @upgradable_versions do
    rollouts
    |> Map.new(fn
      {id, %Entry{} = entry} -> {id, struct(Entry, Map.from_struct(entry))}
      {id, other} -> {id, other}
    end)
    |> accept(watermark)
  end

  defp upgrade(version, _rollouts, _watermark),
    do: {:error, {:unsupported_rollout_checkpoint, version}}

  # One bad entry is one bad entry. Refusing the whole register for it means a single
  # unreadable row — a checkpoint written before ids were keys this build can read, a
  # planted epoch, a sha that is not one — takes every honest rollout record down with it
  # and leaves the node unable to deploy at all. So each entry is held to exactly the
  # validators `build_entry/1` applies on the way in, and the ones that fail are dropped
  # with a logged reason while the rest load.
  defp accept(rollouts, watermark) do
    {kept, refused} =
      Enum.reduce(Map.to_list(rollouts), {%{}, []}, fn pair, {kept, refused} ->
        case validate_loaded(pair) do
          {:ok, id, entry} -> {Map.put(kept, id, entry), refused}
          {:error, reason} -> {kept, [reason | refused]}
        end
      end)

    Enum.each(Enum.reverse(refused), fn reason ->
      Logger.warning(
        "rollout registry dropped an unreadable checkpoint entry: #{inspect(reason)}"
      )
    end)

    {:ok, kept, max(watermark, derived_lane_w_epoch(kept))}
  end

  # Field access is deliberately by `Map.get/2`: a struct-shaped term missing a key is an
  # entry to refuse, not an exception to raise out of `init/1`.
  defp validate_loaded({id, %Entry{} = entry}) do
    with {:ok, id} <- loaded_id(id),
         :ok <- loaded_shape(id, entry) do
      {:ok, id, entry}
    end
  end

  defp validate_loaded({id, other}), do: {:error, {:not_an_entry, key_label(id), describe(other)}}

  # An id that is an atom is a checkpoint written before map keys were tagged: every key
  # went to disk bare, and `Wire.load/1` resolves a bare key that names an existing atom
  # back into that atom. A rollout id spelling a word (`"nil"`, `"error"`) came back as
  # `nil` or `:error` and matched nothing here. It is migrated on read rather than refused,
  # because the entry beside it still says what its id was and the two agree.
  defp loaded_id(id) when is_binary(id) and id != "", do: {:ok, id}
  defp loaded_id(id) when is_atom(id) and not is_nil(id), do: {:ok, Atom.to_string(id)}
  defp loaded_id(nil), do: {:ok, "nil"}
  defp loaded_id(id), do: {:error, {:invalid_rollout_key, describe(id)}}

  defp loaded_shape(id, entry) do
    attrs = %{
      artifact_id: Map.get(entry, :artifact_id),
      module: Map.get(entry, :module),
      epoch: Map.get(entry, :epoch),
      nodes: Map.get(entry, :nodes),
      component_sha256: Map.get(entry, :component_sha256)
    }

    with {:ok, ^id} <- fetch_binary(attrs, :artifact_id),
         :ok <- loaded_module(attrs),
         {:ok, _epoch} <- fetch_epoch(attrs),
         :ok <- loaded_nodes(attrs),
         {:ok, _sha} <- fetch_component_sha256(attrs),
         :ok <- loaded_fields(entry) do
      :ok
    else
      {:ok, other} -> {:error, {:id_mismatch, id, other}}
      {:error, reason} -> {:error, {id, reason}}
    end
  end

  # Looser than `fetch_module/1` on purpose, and for the reason the moduledoc gives: a
  # forged module name this VM has not interned comes back from the checkpoint as the
  # binary it was written as, and "this node has not loaded that module" is a true thing to
  # record about a rollout that happened before the reboot. What `deploying/2` refuses is a
  # caller *presenting* such a name; what this refuses is an entry with no name at all.
  defp loaded_module(%{module: module}) when is_atom(module) and not is_nil(module), do: :ok
  defp loaded_module(%{module: module}) when is_binary(module) and module != "", do: :ok

  defp loaded_module(%{module: other}),
    do: {:error, {:invalid_attribute, :module, describe(other)}}

  # Node names cross the checkpoint the way module names do: `[:safe]` cannot intern one a
  # rebooted VM has never connected to, so `Ouroboros.Upgrade.Wire` hands it back as the
  # binary it was written as. That is a true record of a rollout to a node this VM does not
  # know, not a corrupt one — so both kinds are accepted here, where `deploying/2` takes
  # only the atoms a live caller can have.
  defp loaded_nodes(%{nodes: [_ | _] = nodes}) do
    if Enum.all?(nodes, &(is_atom(&1) or is_binary(&1))),
      do: :ok,
      else: {:error, {:invalid_attribute, :nodes, nodes}}
  end

  defp loaded_nodes(%{nodes: other}), do: {:error, {:invalid_attribute, :nodes, other}}

  defp loaded_fields(entry) do
    cond do
      Map.get(entry, :state) not in @states ->
        {:error, {:invalid_attribute, :state, Map.get(entry, :state)}}

      not Map.has_key?(entry, :eval_report) or not Map.has_key?(entry, :component_sha256) ->
        {:error, {:missing_attribute, :eval_report}}

      not is_binary(Map.get(entry, :created_at)) or not is_binary(Map.get(entry, :updated_at)) ->
        {:error, {:invalid_attribute, :timestamps, nil}}

      not is_map(Map.get(entry, :test_report)) ->
        {:error, {:invalid_attribute, :test_report, describe(Map.get(entry, :test_report))}}

      true ->
        :ok
    end
  end

  defp key_label(id) when is_binary(id) or is_atom(id), do: id
  defp key_label(id), do: describe(id)

  defp describe(term), do: inspect(term, limit: 5, printable_limit: 200)

  defp adapter_call(adapter, function, arguments) do
    apply(adapter, function, arguments)
  rescue
    error -> {:error, {:adapter_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:adapter_failure, kind, inspect(reason)}}
  end

  defp storage_config(opts) do
    case Keyword.fetch(opts, :storage) do
      {:ok, storage} ->
        {:ok, storage}

      :error ->
        case Application.get_env(:ouroboros, :capability_storage) do
          nil -> {:ok, {Jido.Storage.ETS, table: :ouroboros_capabilities}}
          storage -> {:ok, storage}
        end
    end
  end

  defp normalize_storage(storage) do
    {adapter, adapter_opts} = Jido.Storage.normalize_storage(storage)
    {:ok, adapter, adapter_opts}
  rescue
    error -> {:error, {:invalid_capability_storage, Exception.message(error)}}
  end

  defp limit(opts) do
    case Keyword.get_lazy(opts, :limit, fn ->
           Application.get_env(:ouroboros, :capability_rollout_limit, @default_limit)
         end) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> @default_limit
    end
  end

  defp durability_level(Jido.Storage.ETS), do: :ephemeral_checkpoint
  defp durability_level(Ouroboros.Storage.DurableFile), do: :synced_checkpoint
  defp durability_level(_adapter), do: :durable_checkpoint

  defp fetch_binary(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} when is_binary(value) and value != "" -> {:ok, value}
      {:ok, other} -> {:error, {:invalid_attribute, key, other}}
      :error -> {:error, {:missing_attribute, key}}
    end
  end

  # An atom names a module this VM compiled or loaded; `"wasm/<name>"` names a component,
  # which has no module and no atom by design. Every other binary is still refused — the
  # register is binary-*tolerant*, not binary-accepting.
  defp fetch_module(attrs) do
    case Map.fetch(attrs, :module) do
      {:ok, module} when is_atom(module) and not is_nil(module) ->
        {:ok, module}

      {:ok, @wasm_prefix <> name = module} when name != "" ->
        {:ok, module}

      {:ok, other} ->
        {:error, {:invalid_attribute, :module, other}}

      :error ->
        {:error, {:missing_attribute, :module}}
    end
  end

  defp fetch_component_sha256(attrs) do
    case Map.get(attrs, :component_sha256) do
      nil ->
        {:ok, nil}

      sha when is_binary(sha) ->
        if sha =~ ~r/\A[0-9a-f]{#{@sha256_hex}}\z/,
          do: {:ok, sha},
          else: {:error, {:invalid_attribute, :component_sha256, sha}}

      other ->
        {:error, {:invalid_attribute, :component_sha256, other}}
    end
  end

  # One rule, both directions: `deploying/2` calls this and so does `loaded_shape/2`, so a
  # number this build will not read out of a checkpoint is also one it will not write into
  # one. `Ouroboros.Wasm.Artifact.build/2`'s moduledoc warns that a VM-local counter would
  # poison this register's watermark past every epoch `Epoch.next/2` mints; the ceiling is
  # where that warning stops being only a warning.
  defp fetch_epoch(attrs) do
    case Map.fetch(attrs, :epoch) do
      {:ok, epoch} when is_integer(epoch) and epoch > 0 and epoch <= @max_plausible_epoch ->
        {:ok, epoch}

      {:ok, epoch} when is_integer(epoch) and epoch > @max_plausible_epoch ->
        {:error, {:implausible_epoch, epoch, @max_plausible_epoch}}

      {:ok, other} ->
        {:error, {:invalid_attribute, :epoch, other}}

      :error ->
        {:error, {:missing_attribute, :epoch}}
    end
  end

  defp fetch_nodes(attrs) do
    case Map.fetch(attrs, :nodes) do
      {:ok, [_ | _] = nodes} ->
        if Enum.all?(nodes, &is_atom/1),
          do: {:ok, nodes},
          else: {:error, {:invalid_attribute, :nodes, nodes}}

      {:ok, other} ->
        {:error, {:invalid_attribute, :nodes, other}}

      :error ->
        {:error, {:missing_attribute, :nodes}}
    end
  end

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
