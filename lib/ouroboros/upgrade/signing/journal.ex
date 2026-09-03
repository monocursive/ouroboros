defmodule Ouroboros.Upgrade.Signing.Journal do
  @moduledoc """
  The durable record of every decision a signer node made — admitted, issued and refused alike.

  A signature is evidence that a key was applied to some bytes. It is not evidence of
  *why*, of who asked, or of what the signer was shown when it agreed. This journal is
  that half: one entry per request that reached policy, carrying the artifact's identity,
  the modules and dispositions it would have loaded, the node that claimed to ask, the
  decision, and the policy findings behind it.

  Refusals are journaled for the same reason issuances are. A signing service whose log
  contains only successes cannot distinguish "nobody asked" from "something asked two
  thousand times and was turned away", and the second is the shape an attack has.

  This module is data only. `Ouroboros.Upgrade.Signing.Service` owns the storage adapter
  (`config :ouroboros, :signing_journal_storage`) and the checkpoint ordering: a
  signature is never returned to a requester unless the entry describing it has already
  been acknowledged by that adapter. The consequence is deliberate and one-directional —
  the journal may record an issued signature that never reached the requester (a lost
  reply, a dead client), and never a signature that reached one without a record.

  Entries are bounded. Reasons and findings are admitted only while they stay portable
  and small, because a durable log an attacker can grow by choosing its inputs is not a
  log. History is trimmed oldest-first like `Ouroboros.Release.Journal`; an operator who
  needs unbounded retention ships these entries somewhere that has it.

  A findings map is bounded **field by field** when it does not fit as a whole. One
  requester-chosen value inside a verdict — a guest toolchain's `test_report`, which a
  legal manifest carries — must not be able to erase the identity fields beside it, which
  are the ones a refusal is read for. See `findings/1`.

  Module names, struct modules, policy reasons, and node names all cross the checkpoint
  boundary through `Ouroboros.Upgrade.Wire`: `[:safe]` decode must not need this module
  (or any other) already loaded in the reading VM.
  """

  alias Ouroboros.Upgrade.{Beam, ModuleName, Wire}

  @version 1
  # W8. `:admitted` is the first half of a two-phase lane-W signing: the rate limit was
  # charged and the policy accepted the *source* manifest, and only then did the signing node
  # spend a compile on it (docs/WASM.md D15, D23). It is journaled as its own decision because
  # an admission is a real thing this signer did — it committed a rate-limit slot and a policy
  # verdict — and folding it into `:issued` would claim a signature that does not exist yet,
  # while folding it into `:refused` would claim a refusal that never happened.
  @decisions [:issued, :admitted, :refused]
  @lanes [:beam, :wasm]
  @default_limit 500
  @max_detail_bytes 4_096
  @max_journaled_modules 25

  # The share of an entry's budget one value inside an oversized findings map may take.
  # Small enough that every top-level key survives beside every other one.
  @max_finding_bytes 256

  # What a decision was *about*, kept even when the shape of the verdict is hostile. Lane
  # W's identity is the sha, the world, the imports and the start id; lane B's epoch and
  # namespace are the same question asked of the other lane.
  @identity_findings [
    :lane,
    :epoch,
    :namespace,
    :name,
    :world,
    :component_sha256,
    :size,
    :imports,
    :start,
    :recomputed
  ]

  @enforce_keys [:version, :next_sequence, :decisions]
  defstruct @enforce_keys

  @type decision :: :issued | :admitted | :refused

  @typedoc """
  Which signing lane a decision was about.

  `:beam` is `Ouroboros.Upgrade.Artifact`, `:wasm` is `Ouroboros.Wasm.Artifact`, and
  `:unknown` is anything this build did not recognize as either — which is a decision
  worth recording rather than one worth dropping.
  """
  @type lane :: :beam | :wasm | :unknown

  # `:lane` is optional because entries written before lanes existed do not carry it, and
  # `valid?/1` still accepts them — see `record/3`. Everything else has always been there.
  @type entry :: %{
          required(:sequence) => pos_integer(),
          required(:artifact_id) => String.t(),
          required(:epoch) => term(),
          required(:modules) => [map()],
          required(:requester) => node(),
          required(:signer_id) => String.t(),
          required(:decision) => decision(),
          required(:reason) => term(),
          required(:findings) => map(),
          required(:at) => String.t(),
          optional(:lane) => lane()
        }

  @type t :: %__MODULE__{
          version: pos_integer(),
          next_sequence: pos_integer(),
          decisions: [entry()]
        }

  @doc "An empty journal."
  @spec new() :: t()
  def new, do: %__MODULE__{version: @version, next_sequence: 1, decisions: []}

  @doc "The default number of decisions retained."
  @spec default_limit() :: pos_integer()
  def default_limit, do: @default_limit

  @doc """
  Appends one decision, returning the journal to be checkpointed.

  Every field is normalized here rather than at the call site, so an entry cannot carry
  a term the checkpoint could not hold: module lists are capped, reasons and findings
  that are unportable or oversized are replaced by a marker naming why, and anything
  unrecognized becomes a rendered string.

  `:lane` is additive and needs no checkpoint version: `valid?/1` never required a fixed
  key set, so a journal written before lanes existed still loads, and its entries are
  simply entries with no lane recorded — which is the truth about them.
  """
  @spec record(t(), map(), pos_integer()) :: t()
  def record(%__MODULE__{} = journal, attrs, limit \\ @default_limit)
      when is_map(attrs) and is_integer(limit) and limit > 0 do
    entry = %{
      sequence: journal.next_sequence,
      artifact_id: text(Map.get(attrs, :artifact_id)),
      epoch: scalar(Map.get(attrs, :epoch)),
      lane: lane(Map.get(attrs, :lane)),
      modules: modules(Map.get(attrs, :modules, [])),
      requester: requester(Map.get(attrs, :requester)),
      signer_id: text(Map.get(attrs, :signer_id)),
      decision: decision(Map.get(attrs, :decision)),
      reason: bound(Map.get(attrs, :reason)),
      findings: findings(Map.get(attrs, :findings)),
      at: now()
    }

    %{
      journal
      | next_sequence: journal.next_sequence + 1,
        decisions: trim(journal.decisions ++ [entry], limit)
    }
  end

  @doc "The journal as it is written to storage: no atoms a rebooted VM would have to intern."
  @spec to_wire(t()) :: term()
  def to_wire(%__MODULE__{} = journal),
    do: journal |> map_module_names(&ModuleName.to_wire/1) |> Wire.dump()

  @doc "The journal as it is read from storage, resolving names this VM still knows."
  @spec from_wire(term()) :: t() | term()
  def from_wire(term) do
    case Wire.load(term) do
      %__MODULE__{} = journal -> map_module_names(journal, &ModuleName.from_wire/1)
      other -> other
    end
  end

  defp map_module_names(journal, fun) do
    decisions =
      Enum.map(journal.decisions, fn
        %{modules: modules} = entry when is_list(modules) ->
          %{entry | modules: Enum.map(modules, &map_entry_module(&1, fun))}

        entry ->
          entry
      end)

    %{journal | decisions: decisions}
  end

  defp map_entry_module(%{module: module} = entry, fun), do: %{entry | module: fun.(module)}
  defp map_entry_module(entry, _fun), do: entry

  @doc "Whether a term read back from storage is a journal this build may use."
  @spec valid?(term()) :: boolean()
  def valid?(%__MODULE__{} = journal) do
    journal.version == @version and is_integer(journal.next_sequence) and
      journal.next_sequence > 0 and is_list(journal.decisions) and
      Enum.all?(journal.decisions, &valid_entry?/1) and ordered?(journal)
  end

  def valid?(_journal), do: false

  @doc "The decisions, oldest first, in the shape an operator reads."
  @spec public(t()) :: [entry()]
  def public(%__MODULE__{} = journal), do: journal.decisions

  @doc "Counts by decision, for a status surface that must not page through history."
  @spec tally(t()) :: %{
          issued: non_neg_integer(),
          admitted: non_neg_integer(),
          refused: non_neg_integer()
        }
  def tally(%__MODULE__{} = journal) do
    Enum.reduce(journal.decisions, %{issued: 0, admitted: 0, refused: 0}, fn entry, acc ->
      Map.update(acc, entry.decision, 1, &(&1 + 1))
    end)
  end

  defp valid_entry?(entry) do
    is_map(entry) and is_integer(Map.get(entry, :sequence)) and Map.get(entry, :sequence) > 0 and
      Map.get(entry, :decision) in @decisions and is_binary(Map.get(entry, :artifact_id)) and
      is_binary(Map.get(entry, :signer_id)) and is_atom(Map.get(entry, :requester)) and
      is_list(Map.get(entry, :modules)) and is_map(Map.get(entry, :findings)) and
      is_binary(Map.get(entry, :at))
  end

  defp ordered?(journal) do
    sequences = Enum.map(journal.decisions, & &1.sequence)

    sequences == Enum.sort(sequences) and sequences == Enum.uniq(sequences) and
      journal.next_sequence > (List.last(sequences) || 0)
  end

  # The module list is what an operator reads to answer "what would this have loaded",
  # so it keeps names and hashes and drops everything else. It is capped because an
  # artifact's module count is chosen by the requester.
  defp modules(modules) when is_list(modules) do
    kept =
      modules
      |> Enum.take(@max_journaled_modules)
      |> Enum.map(fn
        %{module: module, disposition: disposition, sha256: sha256} ->
          %{module: scalar(module), disposition: scalar(disposition), sha256: text(sha256)}

        other ->
          %{module: render(other), disposition: :unknown, sha256: ""}
      end)

    case length(modules) - length(kept) do
      0 ->
        kept

      dropped ->
        kept ++ [%{module: :truncated, disposition: :truncated, sha256: "", dropped: dropped}]
    end
  end

  defp modules(_other), do: []

  # Bounding the verdict as one term let a single requester-chosen value inside it take the
  # rest down with it. `metadata.test_report` is provenance a guest toolchain writes and a
  # manifest carries, so six kilobytes of it — perfectly legal, `failures: 0`, signed — put
  # the whole findings map over the ceiling and collapsed it to `%{too_large: "..."}`. What
  # was lost is exactly what a refusal is read for: `component_sha256`, `world`, `imports`,
  # `start`. Those are tens of bytes each and were never the problem.
  #
  # So an oversized verdict is bounded value by value instead, one level deeper for a value
  # that is itself a map — which is where a `test_report` sits beside the `author` that has
  # to survive it. The result is still held to the entry's own budget, and if even that does
  # not fit, the identity keys are kept and everything else becomes a marker.
  defp findings(findings) when is_map(findings) and not is_struct(findings) do
    if Beam.portable_term?(findings) and fits?(findings),
      do: findings,
      else: per_field(findings)
  end

  defp findings(_other), do: %{}

  defp per_field(findings) do
    shrunk = Map.new(findings, fn {key, value} -> {scalar(key), finding(value, 1)} end)

    if fits?(shrunk), do: shrunk, else: identity(shrunk)
  end

  defp finding(value, depth) do
    cond do
      Beam.portable_term?(value) and
          byte_size(:erlang.term_to_binary(value)) <= @max_finding_bytes ->
        value

      # A map is opened up before it is given up on, whichever of the two bounds it failed:
      # one unportable pid in a provenance map must not cost the author beside it any more
      # than one oversized report does.
      depth > 0 and is_map(value) and not is_struct(value) ->
        Map.new(value, fn {key, inner} -> {scalar(key), finding(inner, depth - 1)} end)

      not Beam.portable_term?(value) ->
        %{unportable: render(value)}

      true ->
        %{too_large: render(value)}
    end
  end

  # The floor: a verdict whose *shape* is hostile — thousands of small keys, so bounding
  # each one bounds nothing — still records what the decision was about.
  defp identity(shrunk) do
    kept =
      shrunk
      |> Map.take(@identity_findings)
      |> Map.new(fn {key, value} -> {key, finding(value, 0)} end)
      |> Map.put(:findings, :too_large)

    if fits?(kept), do: kept, else: %{too_large: :findings}
  end

  defp fits?(term), do: byte_size(:erlang.term_to_binary(term)) <= @max_detail_bytes

  # Everything below arrives from a requester's artifact or a policy's verdict, and lands
  # in a durable file. Portable and small, or a marker saying it was neither.
  defp bound(nil), do: nil

  defp bound(term) do
    cond do
      not Beam.portable_term?(term) -> %{unportable: render(term)}
      byte_size(:erlang.term_to_binary(term)) > @max_detail_bytes -> %{too_large: render(term)}
      true -> term
    end
  end

  defp decision(decision) when decision in @decisions, do: decision
  defp decision(_other), do: :refused

  defp lane(lane) when lane in @lanes, do: lane
  defp lane(_other), do: :unknown

  defp requester(node) when is_atom(node) and not is_nil(node), do: node
  defp requester(_other), do: :unknown

  defp text(value) when is_binary(value), do: value
  defp text(value), do: render(value)

  defp scalar(value) when is_atom(value) or is_binary(value) or is_number(value), do: value
  defp scalar(value), do: render(value)

  defp trim(decisions, limit) when length(decisions) > limit, do: Enum.take(decisions, -limit)
  defp trim(decisions, _limit), do: decisions

  defp render(term), do: inspect(term, limit: 10, printable_limit: 200)

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
