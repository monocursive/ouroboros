defmodule Ouroboros.Provider.Native.Replay.Model do
  @moduledoc """
  The `Model` behaviour, answered from the record instead of from a provider.

  R2's half of the model seam. `Ouroboros.Provider.Native.Model.stream/3` is a pure
  dispatch on a module and the loop takes `state.model_module`, so a replay needs no
  change in the loop at all: it hands this module in, and every `call_model/2` is served
  by the `model_result` record whose `iteration` matches.

  ## Where the script lives

  In the replaying process's own dictionary, and deliberately. `Loop.run_turn/2` runs the
  whole turn — including `Enum.reduce` over the stream — in the process that called it, so
  a per-process script is race-free by construction and needs no supervisor, no registry
  and no cleanup. A module-level table would have to be keyed by something, and the only
  honest key is the process.

  ## The request digest is checked here, not afterwards

  `call_model/2` digests `Model.project/2` of the wire request *before* streaming, and the
  `model_call` record holds that digest. This module holds the same request in its hand at
  the same moment, so the comparison happens where the evidence is: a mismatch returns
  `{:error, {:replay_diverged, …}}`, the loop fails the turn by name, and the engine reads
  the divergence back out. Checking it later would mean re-deriving a request that had
  already been answered by chunks it did not ask for.

  `project/1` delegates to the module the live run would have used — the node's configured
  `Model.module/0` unless the engine names another — because a projection is the *sending*
  module's own lossy view. Projecting through this module instead would digest the string
  "Ouroboros.Provider.Native.Replay.Model" and call every turn divergent.
  """

  @behaviour Ouroboros.Provider.Native.Model

  alias Ouroboros.Provider.Native.Journal
  alias Ouroboros.Provider.Native.Model

  @script :"$ouroboros_replay_model_script"
  @divergence :"$ouroboros_replay_model_divergence"

  @typedoc """
  One recorded model round-trip: the `model_call` record's provenance and the
  `model_result` record's chunks, already decoded into the loop's chunk vocabulary.
  """
  @type call :: %{
          iteration: pos_integer(),
          seq: pos_integer(),
          at: String.t() | nil,
          turn_id: String.t() | nil,
          request_sha256: String.t() | nil,
          chunks: [tuple()]
        }

  @doc """
  Arms this process to answer one turn's model calls from the record.

  `delegate` is the module whose projection the recorded `request_sha256` was taken
  through. Clearing the previous turn's divergence is part of arming: a turn is verified or
  refused on its own evidence, never on the last turn's.
  """
  @spec install([call()], module()) :: :ok
  def install(calls, delegate) when is_list(calls) and is_atom(delegate) do
    Process.put(@script, %{calls: calls, delegate: delegate})
    Process.delete(@divergence)
    :ok
  end

  @doc "Forgets the script, so a stray call after a turn fails loudly rather than replaying it."
  @spec uninstall() :: :ok
  def uninstall do
    Process.delete(@script)
    :ok
  end

  @doc "The divergence this module refused on, or `nil`."
  @spec divergence() :: map() | nil
  def divergence, do: Process.get(@divergence)

  @doc """
  The `at` of the `model_result` record currently being streamed.

  D9's clock substitution needs a record's instant at the moment its events are emitted,
  and the loop emits text and usage events from inside `consume/5` — after this module has
  handed the stream over and before anything else runs. So the instant is published here
  and read by the engine's `emit`.
  """
  @spec current_at() :: String.t() | nil
  def current_at do
    case Process.get(:"$ouroboros_replay_model_at") do
      at when is_binary(at) -> at
      _unset -> nil
    end
  end

  @impl true
  def stream(request, _opts) do
    case Process.get(@script) do
      %{calls: [call | rest], delegate: delegate} = script ->
        Process.put(@script, %{script | calls: rest})
        answer(call, request, delegate)

      %{calls: [], delegate: _delegate} ->
        {:error, diverge(%{field: "model_call_count", expected_sha256: nil, got_sha256: nil})}

      _unarmed ->
        {:error, {:replay_model_unarmed, request[:turn_id]}}
    end
  end

  @impl true
  def project(request) do
    case Process.get(@script) do
      %{delegate: delegate} when delegate != __MODULE__ ->
        {:ok, Model.project(delegate, request)}

      # No delegate to speak for: say so rather than digesting this module's own name and
      # calling the difference a divergence in the conversation.
      _unarmed ->
        {:error, :no_delegate}
    end
  end

  @impl true
  def available?, do: true

  @impl true
  def credential_report, do: []

  # ------------------------------------------------------------------ answering

  defp answer(call, request, delegate) do
    got = Journal.digest(Model.project(delegate, request))

    cond do
      is_nil(call.request_sha256) ->
        # A record that never carried a digest cannot contradict one. The conversation
        # digest still has to agree at settle, so this is weaker verification, not none.
        deliver(call)

      call.request_sha256 == got ->
        deliver(call)

      true ->
        {:error,
         diverge(%{
           seq: call.seq,
           turn_id: call.turn_id,
           field: "request_sha256",
           expected_sha256: call.request_sha256,
           got_sha256: got
         })}
    end
  end

  defp deliver(call) do
    Process.put(:"$ouroboros_replay_model_at", call.at)
    {:ok, call.chunks}
  end

  defp diverge(fields) do
    divergence = Map.merge(%{seq: nil, turn_id: nil, field: nil}, fields)
    Process.put(@divergence, divergence)
    {:replay_diverged, divergence}
  end
end
