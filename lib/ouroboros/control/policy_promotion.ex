defmodule Ouroboros.Control.PolicyPromotion do
  @moduledoc """
  The durable record of what a signed policy component has *earned* the right to resolve
  (docs/SELF.md §S2, S-D22).

  `Ouroboros.Wasm.PolicyEngine` honours a component's `allow` only for a tool named in
  `config :ouroboros, :policy_allowable_tools`, empty by default, because a component asked
  about every call the rules did not decide and honoured unconditionally would be a blanket
  approval channel with a signature on it (docs/WASM.md D20). That list is an operator typing a
  tool name. This module is the other way in, and the only one: a tool is added here when the
  component was replayed against decisions humans made on this node and contradicted none of
  them, and it is removed the moment a human contradicts it once.

  It holds **one policy**: a name and a component sha256. Promoting a tool for a different name,
  or for the same name at different bytes, is refused until the record is cleared. That is the
  point rather than a simplification — a re-deployed policy is different bytes and has earned
  nothing, and a record that carried a tool across a re-deploy would be a widening nobody
  performed.

      %{
        policy_name: "no-network-shell",
        component_sha256: "…",
        tools: %{"read" => %{promoted_at: …, seq: 4, actor: "operator:ana", evidence: %{…}}},
        demotions: [%{tool: "read", at: …, seq: 9, reason: :human_contradiction, …}]
      }

  A tool is allowable when its promotion's sequence number is greater than every demotion's for
  that tool. The sequence is the record's own counter rather than the wall clock: a promotion
  and a demotion in the same microsecond would be indistinguishable by timestamp, and the
  direction that mistake falls in is the wide one.

  ## The write discipline, and where it is deliberately asymmetric

  `Ouroboros.Control.Grants`': write the checkpoint, fsync it, and only then acknowledge and
  apply in memory. A checkpoint that fails is not applied and not reported as promoted, so a
  storage fault narrows authority. The uncomfortable half is the same one `Grants` states about
  a revocation: a **demotion** whose checkpoint fails has not happened either, the tool stays
  promoted, and `demote/4` returning an error means exactly that — the caller's next move is to
  retry it or to take the policy out of `config :ouroboros, :wasm_policy`.

  The ledger sits on opposite sides of the two:

    * A **promotion** writes its `:policy_promotion` entry *first*, and a ledger that refuses
      refuses the promotion. A widening nobody can account for afterwards is the thing this
      lane exists to prevent.
    * A **demotion** and a **clear** write theirs *after* the checkpoint, and a ledger that
      refuses is logged rather than obeyed. This is `Ouroboros.Control.Permissions`' rule for
      an unrecordable answer, verbatim and for its reason: an allow nobody can account for has
      not been granted, but refusing without an audit entry is still refusing.

  ## What is not here

  No model, no classifier, and no promotion without a named human actor: `promote/6` takes one
  and refuses an empty one. Nothing in this module decides *whether* a tool has earned
  promotion — that is `Ouroboros.Wasm.PolicyEngine.promote/4`, which re-runs the replay against
  the corpus before it calls this. This module holds the answer and the audit.

  Storage comes from `config :ouroboros, :policy_promotion_storage`: ETS in development and
  test, a synced `Ouroboros.Storage.DurableFile` in production. ETS means the record dies with
  the VM and every tool starts unpromoted, which is the safe direction to fail.
  """

  use GenServer

  require Logger

  alias Ouroboros.Agent.EffectLedger

  @store_key {:ouroboros, :policy_promotion, 1}
  @checkpoint_version 1

  # How many demotions the record keeps. A demotion is the durable statement that a human
  # contradicted this component, so it is worth keeping many; it is not worth keeping an
  # unbounded list in an object that is fsynced on every write. The newest are kept, and the
  # *current* state of a tool never depends on an evicted one — only demotions newer than a
  # promotion can matter, and a promotion is what a demotion older than it was already answered
  # by.
  @max_demotions 200

  @actions [:promote, :demote, :clear]

  @type server :: GenServer.server()
  @type evidence :: %{
          required(:report_sha256) => String.t(),
          required(:decisions) => non_neg_integer(),
          required(:contradictions) => non_neg_integer(),
          optional(:replayed_at) => String.t()
        }
  @type promotion_record :: %{
          policy_name: String.t() | nil,
          component_sha256: String.t() | nil,
          tools: %{String.t() => map()},
          demotions: [map()]
        }

  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Records that `tool` has earned an `allow` from `name` at `sha`, on `evidence`, for `actor`.

  `evidence` is `Ouroboros.Wasm.PolicyEngine.replay/2`'s numbers for that tool — a
  `report_sha256`, a `decisions` count and a `contradictions` count — and this module stores
  them rather than judging them. `actor` names the human who promoted: it is required, it is
  not interpreted, and it is what the ledger entry is recorded against.

  Refused when the record already holds a different policy name or different component bytes.
  Clear it first, deliberately, rather than letting a promotion move the record's identity out
  from under the tools already in it.
  """
  @spec promote(String.t(), String.t(), String.t(), evidence(), String.t(), server()) ::
          {:ok, promotion_record()} | {:error, term()}
  def promote(name, sha, tool, evidence, actor, server \\ __MODULE__) do
    GenServer.call(server, {:promote, name, sha, tool, evidence, actor})
  catch
    :exit, reason -> {:error, {:policy_promotion_unavailable, reason}}
  end

  @doc """
  Withdraws `tool`'s promotion for `name`. Narrowing, and idempotent.

  `reason` is a map: `:reason` (an atom — `:human_contradiction` is the canary's), and
  optionally the `:fingerprint` of the human answer that contradicted the component and the
  `:session_id` it came from. Never the command line: a demotion is a fact about a tool, and
  the digest is what makes it traceable to the `:permission` entry beside it.

  A tool that is not promoted is `:ok` with no write — there is nothing to narrow.
  """
  @spec demote(String.t(), String.t(), map(), server()) :: :ok | {:error, term()}
  def demote(name, tool, reason, server \\ __MODULE__) do
    GenServer.call(server, {:demote, name, tool, reason})
  catch
    :exit, reason -> {:error, {:policy_promotion_unavailable, reason}}
  end

  @doc """
  Forgets the whole record: the policy name, the bytes, and every tool promoted under them.

  The one way to point this node's promotion record at a different policy or at re-deployed
  bytes, and it is deliberately a separate act with a named actor on it.
  """
  @spec clear(String.t(), server()) :: :ok | {:error, term()}
  def clear(actor, server \\ __MODULE__) do
    GenServer.call(server, {:clear, actor})
  catch
    :exit, reason -> {:error, {:policy_promotion_unavailable, reason}}
  end

  @doc """
  The tools `name` may currently resolve: promoted, and not demoted since.

  `[]` for any other name, and `[]` when the authority cannot answer. This is read on the
  permission path by `Ouroboros.Wasm.PolicyEngine.allowable_tools/1`, so every failure is the
  empty list: an authority that cannot answer has not widened anything.
  """
  @spec allowable_tools(String.t(), server()) :: [String.t()]
  def allowable_tools(name, server \\ __MODULE__)

  def allowable_tools(name, server) when is_binary(name) and name != "" do
    GenServer.call(server, {:allowable_tools, name})
  catch
    _kind, _reason -> []
  end

  def allowable_tools(_name, _server), do: []

  @doc "The policy this record is bound to, `{name, component_sha256}`, or `nil`."
  @spec policy(server()) :: {String.t(), String.t()} | nil
  def policy(server \\ __MODULE__) do
    GenServer.call(server, :policy)
  catch
    _kind, _reason -> nil
  end

  @doc "The whole record, its durability, and the tools currently allowable."
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
        allowable_tools: []
      }
  end

  @doc false
  def checkpoint_key, do: @store_key

  @doc "The actions a `:policy_promotion` ledger entry may name."
  @spec actions() :: [atom()]
  def actions, do: @actions

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
         durability: durability_level(adapter)
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:promote, name, sha, tool, evidence, actor}, _from, state) do
    with {:ok, name} <- policy_name(name),
         {:ok, sha} <- component_sha(sha),
         {:ok, tool} <- tool_name(tool),
         {:ok, actor} <- actor_name(actor),
         {:ok, evidence} <- evidence(evidence),
         :ok <- bound_to(state.record, name, sha),
         # The ledger first, and a refusal here is the promotion's refusal: a widening nobody
         # can account for afterwards has not been earned.
         :ok <-
           ledger_write(state, :promote, name, sha, tool, actor, %{
             decisions: evidence.decisions,
             contradictions: evidence.contradictions,
             report_sha256: evidence.report_sha256
           }) do
      seq = state.seq + 1

      record = %{
        state.record
        | policy_name: name,
          component_sha256: sha,
          tools:
            Map.put(state.record.tools, tool, %{
              promoted_at: now(),
              seq: seq,
              actor: actor,
              evidence: evidence
            })
      }

      persist(record, seq, {:ok, record}, state)
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:demote, name, tool, reason}, _from, state) do
    with {:ok, name} <- policy_name(name),
         {:ok, tool} <- tool_name(tool),
         {:ok, reason} <- demotion_reason(reason) do
      cond do
        state.record.policy_name != name ->
          # Nothing to narrow: this record is not that policy's. Said as `:ok` rather than as an
          # error because a caller narrowing something that is already not there has got what
          # it asked for.
          {:reply, :ok, state}

        not Map.has_key?(state.record.tools, tool) ->
          {:reply, :ok, state}

        true ->
          seq = state.seq + 1

          demotion =
            reason
            |> Map.merge(%{tool: tool, at: now(), seq: seq})
            |> Map.take([:tool, :at, :seq, :reason, :fingerprint, :session_id])

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
                  Map.get(reason, :session_id) || "runtime",
                  Map.take(demotion, [:reason, :fingerprint, :session_id])
                )

              {:reply, :ok, applied}

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
              actor,
              %{}
            )

          {:reply, :ok, applied}

        other ->
          other
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:allowable_tools, name}, _from, state),
    do: {:reply, allowable(state.record, name), state}

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
    {:reply,
     %{
       durability: state.durability,
       policy_name: state.record.policy_name,
       component_sha256: state.record.component_sha256,
       tools: state.record.tools,
       demotions: state.record.demotions,
       allowable_tools: allowable(state.record, state.record.policy_name)
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

  # A tool is allowable when it is promoted for *this* name and nothing has demoted it since.
  # `nil` is not a name: an unbound record allows nothing.
  defp allowable(%{policy_name: bound} = record, name)
       when is_binary(name) and name != "" and bound == name do
    record.tools
    |> Enum.filter(fn {tool, %{seq: promoted}} ->
      promoted > newest_demotion(record.demotions, tool)
    end)
    |> Enum.map(&elem(&1, 0))
    |> Enum.sort()
  end

  defp allowable(_record, _name), do: []

  defp newest_demotion(demotions, tool) do
    demotions
    |> Enum.filter(&(Map.get(&1, :tool) == tool))
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
         replayed_at: replayed_at(Map.get(evidence, :replayed_at))
       }}
    else
      _malformed -> {:error, {:invalid_promotion_evidence, Map.keys(evidence) |> Enum.sort()}}
    end
  end

  defp evidence(other), do: {:error, {:invalid_promotion_evidence, describe(other)}}

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

  defp ledger_write(state, action, name, sha, tool, actor, result) do
    attrs = %{
      id: "polprom_" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false),
      effect: :policy_promotion,
      principal: actor,
      attempt: %{
        policy_name: name,
        tool: tool,
        action: action,
        component_sha256: sha,
        actor: actor,
        node: node()
      },
      authority: %{decision: action, reason: nil},
      cause: %{signal_id: to_string(action), signal_type: "policy_promotion"},
      result: result
    }

    case EffectLedger.record_settled(attrs, state.ledger) do
      {:ok, _entry, _disposition} ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "policy #{action} not recorded in the effect ledger: #{inspect(reason)}; " <>
            "policy=#{inspect(name)} tool=#{inspect(tool)}"
        )

        {:error, {:policy_promotion_unrecordable, reason}}
    end
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
      # can still read is not this module's to do.
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
      Enum.all?(tools, fn {tool, entry} ->
        is_binary(tool) and is_map(entry) and is_integer(Map.get(entry, :seq))
      end) and Enum.all?(demotions, &(is_map(&1) and is_integer(Map.get(&1, :seq))))
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
