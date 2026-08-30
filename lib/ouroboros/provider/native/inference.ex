defmodule Ouroboros.Provider.Native.Inference do
  @moduledoc """
  The accountability half of a model call: one `:inference` effect-ledger entry, gated.

  R1 §4.2. Three sites in this provider call a model — the turn loop, the compaction
  summariser, and the handoff summariser — and all three are gated the same way, which is
  the only reason this module exists rather than a private function in the loop: a second
  copy of a hard gate is how one of them quietly stops being one.

  The discipline is symmetric with tool calls. `gate/1` writes the attempt **before** the
  request leaves, and a ledger that cannot record it refuses the call; the caller fails by
  name rather than spending tokens nobody can account for. `settle/5` is best effort after
  the stream is consumed, because the call already happened and failing to record how it
  went cannot un-happen it.

  What the entry holds is identities: the session, the turn, the iteration, the model, and
  a digest of the wire request. The prompt itself, the response, and the token stream are
  the content the ledger exists to keep out — `journal_seq` in the result points at the
  `Ouroboros.Provider.Native.Journal` record that does hold them.

  The correlation key across two runs of the same session is
  `(session_id, turn_id, iteration)`. Entry ids embed nanosecond time by design and must
  not be expected to reproduce.
  """

  alias Ouroboros.Agent.EffectLedger

  @doc """
  A fresh effect id for one model round-trip.

  Embeds `node()` for the same reason every other id in this runtime does — an effect id
  is read across a fleet, and a VM-local integer alone collides with the same one
  allocated on another machine — and embeds time so two iterations of one turn cannot
  land on the same id.
  """
  @spec new_effect_id(term()) :: String.t()
  def new_effect_id(scope) do
    digest =
      :sha256
      |> :crypto.hash(
        :erlang.term_to_binary(
          {node(), scope, System.system_time(:nanosecond),
           System.unique_integer([:positive, :monotonic])}
        )
      )
      |> Base.encode16(case: :lower)

    "inference-" <> binary_slice(digest, 0, 32)
  end

  @doc """
  Records the attempt before the request leaves, or says why the call must not happen.

  `attempt` takes `:session_id`, `:turn_id`, `:iteration`, `:model` and `:prompt_sha256`;
  `opts` takes `:principal`, `:cause` (the `signal_type` string) and `:constraints` (the
  subagent link, when there is one).
  """
  @spec gate(String.t(), map(), keyword()) :: :ok | {:error, term()}
  def gate(effect_id, attempt, opts) do
    attrs = %{
      id: effect_id,
      effect: :inference,
      principal: Keyword.fetch!(opts, :principal),
      attempt:
        %{
          session_id: attempt[:session_id],
          turn_id: attempt[:turn_id],
          iteration: attempt[:iteration],
          model: attempt[:model],
          provider: :native,
          prompt_sha256: attempt[:prompt_sha256],
          node: node()
        }
        |> reject_nils(),
      # The no-grant shape the permissions engine already writes. There is no grant to
      # snapshot for an effect the runtime originates on a session's behalf, so the entry
      # says what admitted it and links nothing rather than borrowing somebody's authority.
      authority:
        %{decision: :allow, reason: Keyword.get(opts, :reason, "session")}
        |> put_constraints(Keyword.get(opts, :constraints)),
      cause: %{
        signal_type: Keyword.get(opts, :cause, "native.inference"),
        signal_id: effect_id
      }
    }

    case safe(fn -> EffectLedger.record_started(attrs) end) do
      {:ok, _entry, _disposition} -> :ok
      other -> {:error, other}
    end
  end

  @doc """
  Settles a started attempt with what the call cost and where its record lives.

  `journal_seq` points at the `model_result` journal record; `usage` is the provider's own
  token map, read for counts only. A provider that reported no counts reports none — an
  absent key is a fact and a zero would be a claim.
  """
  @spec settle(String.t(), atom(), integer(), non_neg_integer() | nil, map()) :: :ok
  def settle(effect_id, status, duration_ms, journal_seq, usage) do
    outcome = %{
      status: if(status == :completed, do: :ok, else: :failed),
      result:
        reject_nils(%{
          status: status,
          duration_ms: duration(duration_ms),
          output_bytes: count(usage, :output_bytes),
          journal_seq: journal_seq,
          input_tokens: count(usage, :input_tokens),
          output_tokens: count(usage, :output_tokens)
        })
    }

    outcome =
      if status == :completed,
        do: outcome,
        else: Map.put(outcome, :error, {:inference_not_completed, status})

    _ = safe(fn -> EffectLedger.settle(effect_id, outcome) end)
    :ok
  end

  @doc """
  The `@inference_statuses` value a failure reason maps onto.

  A request the model client's admission control never let out is a capacity problem; a
  stream that started and broke is a provider problem; a model that answered with an error
  is neither. A reader counting one as the other would tune the wrong thing.
  """
  @spec status_of(term()) :: atom()
  def status_of({:model_capacity_timeout, _detail}), do: :capacity_timeout
  def status_of({:model_capacity_exhausted, _detail}), do: :capacity_timeout
  def status_of({:stream_failed, _detail}), do: :stream_failed
  def status_of({:stream_exited, _detail}), do: :stream_failed
  def status_of(_reason), do: :failed

  @doc "What the caller is told when the ledger could not record the call before it ran."
  @spec unrecordable_message(term()) :: String.t()
  def unrecordable_message(reason) do
    "Refused: the effect ledger could not record this model call before it ran, so it " <>
      "did not run. A model call nobody can account for afterwards is what that ledger " <>
      "exists to prevent (#{inspect(reason, limit: 6)})."
  end

  defp put_constraints(authority, nil), do: authority
  defp put_constraints(authority, constraints) when map_size(constraints) == 0, do: authority
  defp put_constraints(authority, constraints), do: Map.put(authority, :constraints, constraints)

  defp count(usage, key) when is_map(usage) do
    case Map.get(usage, key) || Map.get(usage, Atom.to_string(key)) do
      value when is_integer(value) and value >= 0 -> value
      _absent -> nil
    end
  end

  defp count(_usage, _key), do: nil

  defp duration(value) when is_integer(value) and value >= 0, do: value
  defp duration(_value), do: nil

  defp reject_nils(map), do: Map.reject(map, fn {_key, value} -> is_nil(value) end)

  defp safe(fun) do
    fun.()
  rescue
    error -> {:error, {:effect_ledger_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:effect_ledger_failure, kind, inspect(reason)}}
  end
end
