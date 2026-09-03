defmodule Ouroboros.Wasm.Surface do
  @moduledoc """
  What lane W says about itself, for `wasm.status` and `wasm.list` (docs/WASM.md W5).

  Reporting, and only reporting. Nothing here starts the helper, loads a component,
  instantiates anything, or writes to the store: helper presence is one `File.regular?`,
  the pool is asked for the state it already holds and only when a pool process is already
  running, and the store and the rollout register are read. A node that has never built the
  helper answers this verb as readily as one that runs it hourly, and answering does not
  change that.

  ## Absence is a posture

  The helper is opt-in by presence on disk (`Ouroboros.Wasm`), so "no helper here" is an
  operator's decision and not a fault. `helper.present` is that decision, `helper.phase` is
  `:absent` when this node runs no pool process at all, and neither is an error. The verb
  is `:read` for the same reason: it tells an operator what their node would do, without
  doing any of it.

  ## Every key, every time

  A field this node cannot answer is `nil`, never a missing key and never `false`. A
  fail-closed read — an unreadable store directory, a rollout register that is not running
  — is exactly the case a client most needs to tell apart from "zero", and a shape that
  changed under it would make that impossible without a schema. `false` and `0` mean what
  they say; `nil` means this node does not know.

  The one exception is the helper's own `limits` table, which is projected from whatever
  integers the helper's `doctor` report carried rather than from a list restated here: it
  is the helper's contract, it grows, and this side should not need editing when it does.

  ## No absolute paths

  `helper.path` and `store.root` are basenames. Both verbs are `:read` — the lowest scope
  the gateway has — and an absolute path is a fact about the operator's filesystem rather
  than about lane W: it names the install prefix, and often the account, to anybody who may
  merely look. What a reader wants from those fields is *which* helper binary and *whether*
  a store is configured, and a basename answers both.

  ## Nothing helper-written reaches the wire unbounded

  The doctor report, the world strings and a broken pool's reason are all somebody else's
  words. They are cut to fixed ceilings here, and a reason is rendered with `inspect/2`
  before it is cut, so no pid, ref or port ever reaches a client as a term.
  """

  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.{Boot, Pool, Store}

  # The most rows either list returns. The rollout register retains 200 by its own
  # configuration and the store's ceiling is bytes rather than files, so in practice only
  # `components` can reach this — and a client compares the list's length against the
  # count beside it to see that it did.
  @max_rows 512

  # How much of somebody else's prose is worth keeping: a world id, a wasmtime version, a
  # broken pool's rendered reason. Generous for every legitimate value and small enough
  # that a helper writing nonsense cannot make this answer large.
  @max_text_bytes 512

  # The most world strings a helper's report contributes. The helper implements one world;
  # eight leaves room for a build that offers more without letting a hostile one flood a
  # status map.
  @max_worlds 8

  # The most entries the projected `limits` table holds. The helper reports sixteen.
  @max_limit_keys 32

  # The most readable roots the sandbox projection names. A node's own are four; the rest are
  # an operator's `helper_readable`, and a listing is not a place to repeat a long one.
  @max_readable_roots 16

  # The register's own states, restated so a state with no rollouts in it is still reported
  # as zero rather than as a missing key. A sixth state the register grows appears here the
  # moment an entry is in it, because the counts are folded over what is actually held.
  @states [:deploying, :live, :superseded, :rolled_back, :quarantined]

  @doc """
  This node's lane-W posture: the helper, the store, the rollout register, and boot.

  `opts` names the pool, register and store a caller means — tests use it; the gateway
  passes none and gets the node's own singletons.
  """
  @spec status(keyword()) :: map()
  def status(opts \\ []) do
    live = pool_status(opts)

    %{
      node: node(),
      helper: helper(live),
      sandbox: sandbox(live),
      store: store(opts),
      rollouts: rollout_counts(opts),
      boot: %{enabled: Boot.enabled?()}
    }
  end

  @doc """
  Every lane-W rollout the register holds and every component the store holds.

  Both lists are bounded and sorted by their own identity — `artifact_id` and `sha256` —
  so two reads of an unchanged node produce the same answer in the same order. The counts
  beside them are the totals, which is how a client sees a list that was cut.

  Neither list carries a `detail` or an `eval_report`: those are arbitrary terms a
  deployment put there, and this is a listing.
  """
  @spec list(keyword()) :: map()
  def list(opts \\ []) do
    entries = lane_w_entries(opts)
    components = components(opts)
    # W8. Asked once for the whole listing rather than per row: it is two constants off the
    # `doctor` report the pool already accepted, and a listing that started a helper would be a
    # `:read` verb with an effect.
    build = helper_build(opts)

    %{
      node: node(),
      rollouts: rows(entries, &rollout_row(&1, build, opts), & &1.artifact_id),
      rollout_count: count(entries),
      components: rows(components, &component_row/1, & &1.sha256),
      component_count: count(components)
    }
  end

  @doc """
  Projects a `Ouroboros.Wasm.Rollout` outcome onto the shape `wasm.deploy` answers with.

  The outcome a rollout produces is a working term: node atoms as map keys, per-gate
  evidence carrying whatever a failure happened to be, an evaluation summary holding a
  signed spec's own reasons. None of that is wire shape. What a client needs from a deploy
  is which state it settled in, how far it got, and — per node — whether each of the three
  gates passed, with the reason where one did not.

  So every gate becomes `%{outcome: <atom>, detail: <text or nil>}` and every reason is
  rendered and cut here, exactly as `broken_reason` is: a stage failure can carry a
  `File.Error`, an ambiguity carries an exit reason, and neither is a term a client should
  be handed. Node names are strings for the reason `wasm.list`'s are — a node name a
  client turned back into an atom is an atom minted from the wire.
  """
  @spec deployment(map()) :: map()
  def deployment(outcome) when is_map(outcome) do
    %{
      artifact_id: identifier(Map.get(outcome, :artifact_id)),
      name: identifier(Map.get(outcome, :name)),
      module: identifier(Map.get(outcome, :module)),
      component_sha256: identifier(Map.get(outcome, :component_sha256)),
      epoch: integer(Map.get(outcome, :epoch)),
      state: Map.get(outcome, :state),
      stage: Map.get(outcome, :stage),
      nodes: node_list(Map.get(outcome, :nodes)),
      started: started(Map.get(outcome, :started)),
      warnings: warnings(Map.get(outcome, :warnings)),
      eval: eval(Map.get(outcome, :eval_report)),
      deployment: gates(Map.get(outcome, :deployment))
    }
  end

  def deployment(other), do: %{state: :unknown, detail: reason(other)}

  @doc """
  Projects a `Ouroboros.Wasm.Rollout.rollback/2` outcome onto `wasm.rollback`'s answer.

  Smaller than a deployment's, because a rollback proves one thing per node — that this
  capability's wrapper is gone from it, or that something there could not be shown to be —
  and the state is that proof folded together.
  """
  @spec rollback(map()) :: map()
  def rollback(outcome) when is_map(outcome) do
    %{
      artifact_id: identifier(Map.get(outcome, :artifact_id)),
      name: identifier(Map.get(outcome, :name)),
      module: identifier(Map.get(outcome, :module)),
      component_sha256: identifier(Map.get(outcome, :component_sha256)),
      epoch: integer(Map.get(outcome, :epoch)),
      start_id: identifier(Map.get(outcome, :start_id)),
      state: Map.get(outcome, :state),
      nodes: node_list(Map.get(outcome, :nodes)),
      recovery: recovery(Map.get(outcome, :recovery))
    }
  end

  def rollback(other), do: %{state: :unknown, detail: reason(other)}

  # ---------------------------------------------------------------------------
  # Rollout outcomes
  # ---------------------------------------------------------------------------

  defp identifier(value) when is_binary(value), do: cut(value)
  defp identifier(value) when is_atom(value) and not is_nil(value), do: Atom.to_string(value)
  defp identifier(_other), do: nil

  defp integer(value) when is_integer(value), do: value
  defp integer(_other), do: nil

  defp node_list(nodes) when is_list(nodes),
    do: nodes |> Enum.take(@max_rows) |> Enum.map(&node_name/1)

  defp node_list(_other), do: []

  defp started(%{id: id} = started) do
    %{
      id: identifier(id),
      node: started |> Map.get(:node) |> node_or_nil(),
      already_started: Map.get(started, :already_started, false) == true,
      claimed_by: started |> Map.get(:claimed_by) |> identifier(),
      errors: started |> Map.get(:errors, %{}) |> node_keyed(&reason/1)
    }
  end

  defp started(_absent), do: nil

  defp node_or_nil(node) when is_nil(node), do: nil
  defp node_or_nil(node), do: node_name(node)

  # `{:driver_not_a_target, node}` is the only warning this lane has, and a client draws it
  # as a sentence rather than matching on it, so it arrives rendered.
  defp warnings(warnings) when is_list(warnings),
    do: warnings |> Enum.take(@max_rows) |> Enum.map(&reason/1)

  defp warnings(_other), do: []

  defp eval(%{spec: spec, nodes: nodes}) when is_map(spec) do
    %{
      probes: integer(Map.get(spec, :probes)),
      required: required_text(Map.get(spec, :required)),
      budget_ms: integer(Map.get(spec, :budget_ms)),
      nodes: node_keyed(nodes, &evidence/1)
    }
  end

  defp eval(_absent), do: nil

  # `:all` and `{:at_least, n}` are the register's own vocabulary and a client draws them.
  # Rendered as words rather than as `inspect/1`'s spelling of an Elixir term, because
  # `":all"` on a wire is this runtime's syntax leaking into somebody else's client.
  defp required_text(:all), do: "all"
  defp required_text({:at_least, n}) when is_integer(n), do: "at_least #{n}"
  defp required_text(other), do: reason(other)

  defp gates(evidence) when is_map(evidence) do
    node_keyed(evidence, fn node_evidence ->
      %{
        stage: evidence(Map.get(node_evidence, :stage)),
        probe: evidence(Map.get(node_evidence, :probe)),
        eval: evidence(Map.get(node_evidence, :eval)),
        recovery: Map.get(node_evidence, :recovery)
      }
    end)
  end

  defp gates(_other), do: %{}

  defp recovery(recovery) when is_map(recovery),
    do: node_keyed(recovery, fn value -> if is_atom(value), do: value, else: :unknown end)

  defp recovery(_other), do: %{}

  # Map keys become strings before they reach the wire, so a node name never crosses as a
  # term a client could turn back into an atom. Bounded by the same row ceiling as
  # everything else here: a deployment names its own targets, but the map is read out of a
  # registry entry this build may not have written.
  defp node_keyed(map, project) when is_map(map) do
    map
    |> Enum.take(@max_rows)
    |> Map.new(fn {target, value} -> {node_name(target), project.(value)} end)
  end

  defp node_keyed(_other, _project), do: %{}

  # One gate, as an outcome a client branches on and a reason a person reads. The reason is
  # rendered before it is cut, because a stage failure can carry an exception, an exit
  # reason, or a port — and none of those are terms a socket hands out.
  defp evidence(:ok), do: %{outcome: :ok, detail: nil}
  defp evidence(:skipped), do: %{outcome: :skipped, detail: nil}
  defp evidence(:absent), do: %{outcome: :absent, detail: nil}
  defp evidence(nil), do: %{outcome: :unknown, detail: nil}
  defp evidence({:mismatch, detail}), do: %{outcome: :mismatch, detail: reason(detail)}
  defp evidence({:error, detail}), do: %{outcome: :error, detail: reason(detail)}
  defp evidence({:ambiguous, detail}), do: %{outcome: :ambiguous, detail: reason(detail)}

  # An evaluation summary. `satisfied?` is the verdict and the failures are why; both are
  # `Ouroboros.Upgrade.Rollout.Evaluation.summarize/1`'s own bounded shape, rendered here
  # because a failure's reason is a signed spec's word for what went wrong.
  defp evidence(%{satisfied?: satisfied?} = summary) do
    %{
      outcome: if(satisfied? == true, do: :passed, else: :failed),
      detail: summary |> Map.get(:failures, []) |> failures(),
      probes: integer(Map.get(summary, :probes)),
      passed: integer(Map.get(summary, :passed)),
      failed: integer(Map.get(summary, :failed)),
      total_ms: integer(Map.get(summary, :total_ms))
    }
  end

  defp evidence(other), do: %{outcome: :unknown, detail: reason(other)}

  defp failures([]), do: nil
  defp failures(failures) when is_list(failures), do: reason(failures)
  defp failures(_other), do: nil

  # ---------------------------------------------------------------------------
  # The helper
  # ---------------------------------------------------------------------------

  # W16, D25. The OS sandbox the helper runs under, as its own half of the answer rather than
  # a field inside `helper`: an operator asking "is this node containing its helper" is asking
  # about the node's posture, and the answer exists — `:refused` — on a node where there is no
  # helper *because* the posture could not be applied.
  #
  # A node with no pool process has decided nothing, and says so with nulls rather than with a
  # posture nobody has taken. `reason` is rendered and cut like every other term here: it
  # carries a backend's own prose on the `no_backend` path.
  defp sandbox(nil), do: %{posture: nil, backend: nil, reason: nil, readable: []}

  defp sandbox(%{sandbox: %{posture: posture, backend: backend, reason: why} = report}) do
    %{
      posture: posture,
      backend: text(backend),
      reason: reason(why),
      # **Basenames**, for `helper.path`'s and `store.root`'s reason: both wasm verbs are
      # `:read`, the lowest scope this gateway has, and an absolute path names an install
      # prefix and often an account to anyone who may merely look. What a reader gets here is
      # how many roots are in force and which ones they are by name — enough to see that a
      # rejected `helper_readable` list is not in force — and the absolute list stays on the
      # node, in `Ouroboros.Wasm.Pool.status/1`.
      readable: readable(Map.get(report, :readable, []))
    }
  end

  defp readable(roots) when is_list(roots) do
    roots
    |> Enum.take(@max_readable_roots)
    |> Enum.flat_map(fn root -> List.wrap(text(basename(root))) end)
  end

  defp readable(_absent), do: []

  defp helper(live) do
    # The path a *running* pool holds, and this build's resolution only where no pool does.
    # A pool started against another binary is the one that would actually run, so reporting
    # the module's own answer beside it would be a readiness surface describing a helper this
    # node has no intention of spawning.
    path = if live, do: live.helper_path, else: Wasm.helper_path()

    base = %{
      present: File.regular?(path),
      path: basename(path),
      world: Wasm.world(),
      hook_component_budget: Pool.hook_component_budget()
    }

    Map.merge(base, live_helper(live))
  end

  # No pool process on this node — a library start, or a node whose supervision tree runs
  # none. Not a broken helper, and not a helper that failed: nobody has asked for one.
  defp live_helper(nil) do
    %{
      phase: :absent,
      os_pid: nil,
      instances: 0,
      owned: 0,
      pending_drops: 0,
      hook_components: 0,
      usable: nil,
      worlds: [],
      wasmtime: nil,
      limits: nil,
      broken_reason: nil
    }
  end

  defp live_helper(status) do
    report = if is_map(status.doctor), do: status.doctor, else: %{}

    %{
      phase: status.phase,
      os_pid: status.os_pid,
      instances: status.instances,
      owned: status.owned,
      pending_drops: status.pending_drops,
      hook_components: status.hook_components,
      usable: usable(report),
      worlds: worlds(report),
      wasmtime: text(Map.get(report, "wasmtime")),
      limits: limits(report),
      broken_reason: reason(status.broken_reason)
    }
  end

  # `Pool.status/1` is a call on a process that already exists: it reads the state the pool
  # holds and spawns no helper. Whether that process exists is checked first, because the
  # pool's own catch renders an absent one as `:broken` — true of a request, and a lie in a
  # status surface, where "nobody started a pool" and "the helper failed" are the two
  # answers an operator most needs to tell apart.
  defp pool_status(opts) do
    server = Keyword.get(opts, :pool, Pool)

    if running?(server), do: Pool.status(server)
  end

  defp running?(name) when is_atom(name), do: is_pid(Process.whereis(name))
  defp running?(pid) when is_pid(pid), do: Process.alive?(pid)

  # A `{name, node}` or `{:via, …}` server this side cannot check without a call. Answering
  # `true` would hand it to `Pool.status/1`, whose catch renders an unreachable server as
  # `phase: :broken` with an empty `helper_path` — precisely the lie this module exists to
  # avoid, and about a helper nobody has even shown to be missing. Unverifiable is absent.
  defp running?(_unverifiable), do: false

  # A boolean the helper actually sent, or nothing. `usable` is its own probe of whether an
  # engine can be built on this host, and a report that omitted it did not say "no".
  defp usable(report) do
    case Map.get(report, "usable") do
      value when is_boolean(value) -> value
      _absent -> nil
    end
  end

  defp worlds(report) do
    case Map.get(report, "worlds") do
      list when is_list(list) ->
        list |> Enum.take(@max_worlds) |> Enum.flat_map(&List.wrap(text(&1)))

      _absent ->
        []
    end
  end

  # The helper's bounds table, projected as the integers it reported under the names it
  # reported them under. Keys stay strings — they are the helper's, and no atom is minted
  # from a program on the end of a pipe — and only integers survive, so a report that put a
  # map or a list in there contributes nothing rather than an unbounded term.
  #
  # Bounded in **bytes as well as in count**. A count alone bounds nothing: thirty-two keys
  # of a quarter-megabyte each is a multi-megabyte answer crossing `:erpc` on every poll. An
  # over-long key is dropped rather than truncated, because two long keys sharing a prefix
  # would truncate into one — a bound that silently merges somebody else's data is worse
  # than one that omits it.
  #
  # The cut comes before the sort so a hostile table costs one pass rather than a sort of
  # the whole thing. The kept keys are the first `#{@max_limit_keys}` the map yields and are
  # sorted afterwards, which is deterministic for any one report: the same report always
  # projects the same table.
  defp limits(report) do
    case Map.get(report, "limits") do
      table when is_map(table) ->
        table
        |> Enum.filter(fn {key, value} ->
          is_binary(key) and byte_size(key) <= @max_text_bytes and is_integer(value)
        end)
        |> Enum.take(@max_limit_keys)
        |> Enum.sort_by(fn {key, _value} -> key end)
        |> Map.new()

      _absent ->
        nil
    end
  end

  # A pool's broken reason is a term this node built around somebody else's failure, and it
  # can hold a port, a ref or an exit reason. Rendered, then cut.
  defp reason(nil), do: nil
  defp reason(term), do: term |> inspect(limit: 8, printable_limit: @max_text_bytes) |> cut()

  defp text(value) when is_binary(value) do
    case cut(value) do
      "" -> nil
      trimmed -> trimmed
    end
  end

  defp text(_other), do: nil

  # `binary_part/3` can cut inside a multi-byte character, and everything cut here is on its
  # way to a client that is owed valid UTF-8. `Ouroboros.Gateway.Wire` renders an invalid
  # binary as a `%{"_b64" => …}` object rather than a string, and the Rust client's string
  # decode drops an object silently — so a helper whose `wasmtime` or world string ends on a
  # multi-byte character exactly at the ceiling would *disappear* from `ouro wasm doctor`
  # rather than arrive truncated. A helper choosing that boundary on purpose is a helper
  # hiding its own version, which is the one thing this projection exists to show.
  #
  # So the cut retreats to the last whole character — never more than three bytes back in a
  # binary that was valid to begin with — and a binary that is not valid UTF-8 at all
  # becomes `""`, which `text/1` reads as "the helper said nothing". Same shape as
  # `Wire.utf8_prefix/2`, which solves this for event leaves.
  defp cut(value) when byte_size(value) <= @max_text_bytes,
    do: if(String.valid?(value), do: value, else: "")

  defp cut(value), do: value |> binary_part(0, @max_text_bytes) |> retreat(3)

  defp retreat(prefix, 0), do: if(String.valid?(prefix), do: prefix, else: "")

  defp retreat(prefix, tries) do
    if String.valid?(prefix),
      do: prefix,
      else: retreat(binary_part(prefix, 0, byte_size(prefix) - 1), tries - 1)
  end

  # ---------------------------------------------------------------------------
  # The store
  # ---------------------------------------------------------------------------

  # `held` and `components` are the components; `bytes` is every file the store holds,
  # because that is the number `budget_bytes` is compared against by the prune that
  # enforces it. Reporting a subtotal beside a budget would be reporting a number an
  # operator cannot act on.
  defp store(opts) do
    entries = all_entries(opts)

    %{
      root: basename(store_root(opts)),
      budget_bytes: Wasm.config(:store_budget_bytes),
      held: count(components_of(entries)),
      bytes: held_bytes(entries),
      protected: protected(opts)
    }
  end

  defp held_bytes(nil), do: nil
  defp held_bytes(entries), do: Enum.reduce(entries, 0, &(&1.size + &2))

  defp store_root(opts) do
    case Store.root(opts) do
      {:ok, root} -> root
      {:error, _no_data_dir} -> nil
    end
  end

  # An absolute path is a fact about this operator's disk, and `wasm.status`/`wasm.list`
  # are `:read` verbs — the lowest scope the gateway has. The basename is what an operator
  # actually reads them for (which helper binary is this node holding, is the store where
  # this build puts one); the directory it sits in is not on a listing's business.
  defp basename(nil), do: nil
  defp basename(path) when is_binary(path), do: path |> Path.basename() |> cut()

  # `nil` rather than `[]` for a store this node has no directory for or cannot read: an
  # empty store and an unreadable one are different facts and only one of them is safe to
  # draw as "no components here".
  defp all_entries(opts) do
    case Store.list(opts) do
      {:ok, entries} -> entries
      {:error, _unreadable} -> nil
    end
  end

  defp components(opts), do: opts |> all_entries() |> components_of()

  defp components_of(nil), do: nil
  defp components_of(entries), do: Enum.filter(entries, &(&1.kind == :component))

  # How many components a rollout is currently keeping alive, which is the number an
  # operator reads before wondering why a prune reclaimed nothing. The store fails closed on
  # an unreadable register and so does this.
  defp protected(opts) do
    case Store.protected_shas(opts) do
      {:ok, shas} -> MapSet.size(shas)
      {:error, :registry_unavailable} -> nil
    end
  end

  # ---------------------------------------------------------------------------
  # Rollouts
  # ---------------------------------------------------------------------------

  # `total: nil` with an empty `by_state` is a register that did not answer, and it must not
  # be confused with a register holding nothing: zero-filling an unavailable one would draw
  # "no rollouts here" over a node whose rollouts are simply not known.
  defp rollout_counts(opts) do
    case lane_w_entries(opts) do
      nil ->
        %{total: nil, by_state: %{}}

      entries ->
        zeroes = Map.new(@states, &{&1, 0})
        counts = Enum.reduce(entries, zeroes, &Map.update(&2, &1.state, 1, fn n -> n + 1 end))
        %{total: length(entries), by_state: counts}
    end
  end

  # A lane-W entry is one that names component bytes; a lane-B entry deployed modules and
  # belongs to `upgrade.rollouts`, not here.
  #
  # `nil` when the register did not answer. It is a `GenServer.call`, so a node that runs no
  # register exits the caller — which the gateway would render as an unavailable plane for
  # the whole verb, when the honest answer is that three of its four sections are fine and
  # this one is not known.
  defp lane_w_entries(opts) do
    opts
    |> Keyword.get(:registry, Registry)
    |> Registry.list()
    |> Enum.filter(&is_binary(Map.get(&1, :component_sha256)))
  rescue
    _unreadable -> nil
  catch
    :exit, _not_running -> nil
  end

  defp rollout_row(entry, build, opts) do
    %{
      artifact_id: entry.artifact_id,
      name: name_of(entry.module),
      component_sha256: entry.component_sha256,
      epoch: entry.epoch,
      state: entry.state,
      # W8. Which of the two forms this node loads this entry's component from — `precompiled`
      # when the signed manifest declares an artifact for exactly this node's wasmtime and
      # triple and the store holds it, `source` otherwise, and `nil` where this node cannot
      # say: no manifest it can read, or no helper that has reported its build yet. `nil` means
      # "this node does not know", as every other field here does.
      form: form_of(entry, build, opts),
      nodes: entry.nodes |> Enum.take(@max_rows) |> Enum.map(&node_name/1),
      created_at: entry.created_at,
      updated_at: entry.updated_at
    }
  end

  # Read out of the store's own manifest for the row, which is the only durable place a
  # `precompiled` block lives on a loading node: the register keeps the component sha and
  # nothing else (D2, D6). One small file per row, bounded by `@max_rows`.
  #
  # This says which form a load *would* take. It is not a record of one that happened — the
  # register keeps none — and it is deliberately computed the same way `Ouroboros.Wasm.Store.form/4`
  # computes it, so an operator reading this and a node deciding are reading one rule. The one
  # difference is stated where it is made: this does not re-digest the artifact, so a row can
  # read `precompiled` for a file a load will find rotted and fall back on.
  defp form_of(entry, build, opts) do
    with id when is_binary(id) <- Map.get(entry, :artifact_id),
         sha when is_binary(sha) <- Map.get(entry, :component_sha256),
         {:ok, %{precompiled: precompiled}} <- Store.fetch_manifest(id, opts) do
      # `verify: false`: a listing that digested fifty artifacts to draw a column would be a
      # `:read` verb doing a second's work. What this says is which form a load *would* choose
      # on the readings it can see for free; a load re-reads the digest for itself.
      case Store.form(sha, precompiled, build, Keyword.put(opts, :verify, false)) do
        {:precompiled, _path, _sha} -> :precompiled
        {:source, _path, _why} -> :source
        {:error, _unreadable} -> nil
      end
    else
      _unknown -> nil
    end
  rescue
    _unreadable -> nil
  end

  # `connect: false`: this verb is `:read`, and a listing that spawned a helper to answer whether
  # a helper is there would be exactly the effect W5 kept out of it. A node with no accepted
  # report says `nil` rather than starting one to find out.
  #
  # `running?/1` — the same one `helper/1` uses — rather than `Process.whereis/1` alone, because
  # a pool may be named by a pid and `whereis` takes an atom: asking about one would raise
  # inside a `:read` verb.
  defp helper_build(opts) do
    server = Keyword.get(opts, :pool, Pool)
    if running?(server), do: Pool.helper_build(server, connect: false)
  rescue
    _unavailable -> nil
  catch
    :exit, _not_running -> nil
  end

  # One node name out of a register entry. An atom is the ordinary case and a binary is a
  # name this VM never interned — both are ordinary readings of a checkpoint. Anything else
  # is a row worth drawing rather than a verb worth killing: `to_string/1` raises on a map,
  # and inside `safe/1` that would turn one malformed row from a checkpoint this build did
  # not write into `-32006` for the whole listing.
  defp node_name(node) when is_atom(node), do: Atom.to_string(node)
  defp node_name(node) when is_binary(node), do: cut(node)
  defp node_name(other), do: other |> inspect(limit: 5, printable_limit: @max_text_bytes) |> cut()

  # `"wasm/" <> name` is the whole of a lane-W rollout's module field (docs/WASM.md D2): the
  # lane deploys a component and introduces no atom, so what a client draws is the name.
  #
  # Guarded the way `node_name/1` is, and for the same reason: a `module` field read back
  # from a checkpoint this build did not write can be any term, `to_string/1` raises on
  # most of them, and inside `safe/1` one malformed row would become `-32006` for the whole
  # listing instead of one row worth looking at.
  defp name_of("wasm/" <> name), do: cut(name)
  defp name_of(name) when is_binary(name), do: cut(name)
  defp name_of(name) when is_atom(name), do: Atom.to_string(name)
  defp name_of(other), do: other |> inspect(limit: 5, printable_limit: @max_text_bytes) |> cut()

  defp component_row(entry), do: %{sha256: entry.sha256, size: entry.size, mtime: entry.mtime}

  # ---------------------------------------------------------------------------
  # Shared
  # ---------------------------------------------------------------------------

  # Sorted by the row's own identity rather than by the order a directory listing or a map
  # traversal happened to produce, so two reads of an unchanged node agree.
  defp rows(nil, _row, _key), do: []

  defp rows(entries, row, key) do
    entries
    |> Enum.map(row)
    |> Enum.sort_by(key)
    |> Enum.take(@max_rows)
  end

  defp count(nil), do: nil
  defp count(entries), do: length(entries)
end
