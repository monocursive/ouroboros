defmodule Ouroboros.Upgrade.Rollout.Evaluation do
  @moduledoc """
  The behavioural gate a forged capability clears between commit and promotion.

  `Ouroboros.Upgrade.Rollout.Probe` asks one question about code nobody has ever seen:
  does this module start, answer a message, and stop? That is liveness, and a system
  that promotes on liveness alone is self-*modifying* — it can show the new module is
  alive, never that it does what it was forged to do. An evaluation spec is the missing
  evidence.

  ## A spec is data, on purpose

  A spec is a map of probes — an input to send and an expectation to hold against the
  answer — plus a time budget and how many probes must pass. There is no function in it
  anywhere. That is not a limitation being worked around: a spec is embedded in
  `metadata.forge.eval`, *inside* the signed artifact manifest, so the criteria travel
  with the bytes they judge and one flipped byte in either invalidates the signature. A
  closure could not be signed, could not be shipped to a node that has not loaded it,
  and could not be read by a future external signer deciding whether an artifact
  declares gates at all.

      %{
        probes: [
          %{input: %{op: "ping"}, expect: {:contains, "ping"}},
          %{input: "again", expect: {:state_matches, :messages_received, 2}}
        ],
        budget_ms: 2_000,
        max_latency_ms: 500,
        required: :all
      }

  ## What a report is evidence of

  Exactly the probes in the spec, run once, on one node, against one throwaway instance
  of the capability. It says nothing about inputs nobody wrote a probe for, about
  production traffic, or about cost. `total_ms` is wall-clock on a shared VM and is
  noisy at this scale. A passing report means "the declared spec held, here, once" —
  which is strictly more than liveness and strictly less than correctness.

  ## Two clocks

  `budget_ms` is the deadline: it bounds every call, and probes left over when it runs
  out are recorded as exhausted rather than run. `max_latency_ms` is a gate on the
  latency actually observed, checked after the answer arrives — a probe that answers in
  300ms under a 50ms gate failed the gate, which is a more useful thing to record than a
  timeout that hides whether it answered at all.

  ## One agent, ordered probes

  `run/3` starts a single throwaway mesh agent under a unique id and drives every probe
  through it in order, so probe *n* observes whatever probes *1..n-1* left behind. That
  is what makes `{:state_matches, key, value}` worth having, and it means a spec's
  probes are a sequence rather than a set. `:initial_state` seeds that agent, so a
  capability whose behaviour depends on state can still be evaluated declaratively.

  ## The reply an expectation is held against

  `{:equals, value}` and `{:contains, substring}` are matched against the capability's
  *answer*: the `:last_answer` key of its post-exchange state when it declares one — the
  key `Ouroboros.Agent.Worker` already uses for a result — and otherwise the whole state
  map. A capability that wants `{:equals, _}` to mean "it answered this" must publish an
  answer; one that does not is better gated with `{:state_matches, key, value}`, which
  reads a named key out of the agent's state through `Ouroboros.Mesh.state/1`.

  ## Why every path is defended

  This function is called through `:erpc` from the coordinating node, exactly like the
  probe. An escaped exception there is not a failure, it is *transport ambiguity*, and
  ambiguity quarantines a cluster with no automatic exit. A capability that raises has
  failed a probe; it has not made the cluster unknowable, and this module must never let
  those two be confused. So every clause converts exceptions, exits, and throws into
  results, the throwaway agent is stopped in an `after` block on every path, and every
  value that crosses back over the wire is a plain serializable term.
  """

  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.Beam

  @source "ouroboros-rollout-evaluation"

  @spec_keys [:probes, :budget_ms, :max_latency_ms, :required, :initial_state]
  @probe_keys [:input, :expect]

  # Bounds exist because a spec is signed, replicated to every target, and stored in a
  # durable registry. An unbounded spec is an unbounded manifest.
  @max_probes 20
  @max_spec_bytes 16_384
  @max_budget_ms 120_000
  @default_budget_ms 10_000
  @max_reported_failures 5
  @max_reason_bytes 512

  @visibility_retries 20
  @visibility_delay_ms 25

  @type expectation ::
          :any_reply
          | {:equals, term()}
          | {:contains, String.t()}
          | {:state_matches, atom(), term()}

  @type probe :: %{input: term(), expect: expectation()}

  @typedoc "What to start: a module, or a module and the state to seed it with. See `run/3`."
  @type start_spec :: module() | {module(), map()}

  @type spec :: %{
          probes: [probe()],
          budget_ms: pos_integer(),
          max_latency_ms: pos_integer() | nil,
          required: :all | {:at_least, pos_integer()},
          initial_state: map()
        }

  @type result :: %{
          index: non_neg_integer(),
          ms: non_neg_integer(),
          outcome: :passed | :failed,
          reason: term()
        }

  @type report :: %{
          module: module(),
          node: node(),
          probes: non_neg_integer(),
          passed: non_neg_integer(),
          failed: non_neg_integer(),
          total_ms: non_neg_integer(),
          budget_ms: pos_integer(),
          required: :all | {:at_least, pos_integer()},
          within_budget?: boolean(),
          satisfied?: boolean(),
          results: [result()]
        }

  @doc """
  Checks and normalizes an evaluation spec without running anything.

  Every failure is `{:error, {:invalid_eval_spec, reason}}` with a named reason:
  `{:unknown_spec_keys, keys}`, `:probes_required`, `{:too_many_probes, count, max}`,
  `{:probe_input_not_portable, index}`, `{:unknown_expectation, index, rendered}`,
  `{:invalid_budget_ms, rendered}`, `{:invalid_required, rendered}`, and
  `{:eval_spec_too_large, bytes, max}` among them.
  """
  @spec validate(term()) :: {:ok, spec()} | {:error, term()}
  def validate(spec) when is_map(spec) and not is_struct(spec) do
    with :ok <- ensure_known_keys(spec),
         {:ok, probes} <- validate_probes(Map.get(spec, :probes)),
         {:ok, budget_ms} <- validate_budget(Map.get(spec, :budget_ms, @default_budget_ms)),
         {:ok, max_latency_ms} <- validate_latency(Map.get(spec, :max_latency_ms), budget_ms),
         {:ok, required} <- validate_required(Map.get(spec, :required, :all), length(probes)),
         {:ok, initial_state} <- validate_initial_state(Map.get(spec, :initial_state, %{})),
         normalized = %{
           probes: probes,
           budget_ms: budget_ms,
           max_latency_ms: max_latency_ms,
           required: required,
           initial_state: initial_state
         },
         :ok <- ensure_bounded(normalized) do
      {:ok, normalized}
    end
  end

  def validate(other), do: reject({:not_a_map, describe(other)})

  @doc """
  Runs `spec` against `start` on the node this function is executing on.

  `start` is a module, or `{module, initial_state}` — the same start spec
  `Ouroboros.Upgrade.Rollout.Probe.ready?/1` takes, and for the same reason: a lane-W
  capability is one shipped module standing in for every component, so which capability is
  being evaluated is a fact about its state (docs/WASM.md §7.2, D7). Lane B passes the bare
  module and nothing about it changes.

  Returns `{:ok, report}` whenever the spec was driven to completion, failures included:
  a report is the answer, not the verdict. `{:error, reason}` means the evaluation could
  not be performed at all — an invalid spec, a module that will not load, an agent that
  will not start — which is a definite refusal rather than an ambiguity. Nothing raises.

  ## Two sources of seed state, and which one wins

  A spec may carry `:initial_state`, and a start spec may carry state of its own. They are
  merged, and **the start spec wins on conflict**. The start spec is the deployment's
  statement of what is being evaluated — which component, under which config, against which
  helper — while the eval spec is a signed *test* of it. A signed spec that could overwrite
  `:component` would be a test able to redirect the thing it is testing, which is not a
  power a test gets to have. Everything the start spec does not name, the spec still seeds.

  That last sentence is a constraint on the *caller*, and it is the whole rule: precedence
  protects the keys the start spec names, and only those. **A start spec must therefore name
  every key that decides what is being evaluated**, not merely the ones that identify it —
  otherwise a signed spec chooses the rest. For `Ouroboros.Wasm.Capability` those keys are
  `:component`, `:config`, `:name`, `:limits`, `:pool` and `:store_root`: leaving `:limits`
  out lets a spec pick the bounds it is judged under, and leaving `:pool` or `:store_root`
  out lets it pick which helper and which bytes. This module deliberately holds no list of
  them — it must not know any agent's schema — so the obligation lives with whoever builds
  the start spec, and each such agent states its own keys in its own moduledoc.
  """
  @spec run(start_spec(), term(), keyword()) :: {:ok, report()} | {:error, term()}
  def run(start, spec, opts \\ [])

  def run(start, spec, opts) when is_list(opts) do
    case normalize_start(start) do
      {:ok, module, initial_state} ->
        with {:ok, valid} <- validate(spec) do
          execute(module, initial_state, valid)
        end

      :error ->
        {:error, {:invalid_eval_module, describe(start)}}
    end
  end

  def run(_start, _spec, opts), do: {:error, {:invalid_eval_options, describe(opts)}}

  defp normalize_start(module) when is_atom(module) and not is_nil(module),
    do: {:ok, module, %{}}

  defp normalize_start({module, initial_state})
       when is_atom(module) and not is_nil(module) and is_map(initial_state) and
              not is_struct(initial_state),
       do: {:ok, module, initial_state}

  defp normalize_start(_start), do: :error

  @doc "Whether a report satisfies the spec that produced it. Anything unrecognized is a no."
  @spec passed?(term()) :: boolean()
  def passed?(%{satisfied?: satisfied?}) when is_boolean(satisfied?), do: satisfied?
  def passed?(_report), do: false

  @doc """
  Projects a report onto the bounded shape a registry entry can hold.

  Counts and timings survive whole; per-probe detail does not. Only the first
  #{@max_reported_failures} failures are kept, because a durable record of every
  rollout must not grow with the size of the specs it evaluated.
  """
  @spec summarize(term()) :: map()
  def summarize(report) when is_map(report) do
    %{
      node: Map.get(report, :node),
      probes: Map.get(report, :probes),
      passed: Map.get(report, :passed),
      failed: Map.get(report, :failed),
      total_ms: Map.get(report, :total_ms),
      budget_ms: Map.get(report, :budget_ms),
      within_budget?: Map.get(report, :within_budget?),
      satisfied?: passed?(report),
      failures: report |> Map.get(:results, []) |> failures()
    }
  end

  def summarize(other), do: %{satisfied?: false, failures: [], reason: describe(other)}

  defp failures(results) when is_list(results) do
    results
    |> Enum.filter(&(is_map(&1) and Map.get(&1, :outcome) == :failed))
    |> Enum.take(@max_reported_failures)
    |> Enum.map(fn result ->
      %{
        index: Map.get(result, :index),
        ms: Map.get(result, :ms),
        reason: sanitize(Map.get(result, :reason))
      }
    end)
  end

  defp failures(_results), do: []

  # ## Spec validation

  defp ensure_known_keys(spec) do
    case Map.keys(spec) -- @spec_keys do
      [] -> :ok
      unknown -> reject({:unknown_spec_keys, Enum.map(unknown, &describe/1)})
    end
  end

  defp validate_probes(nil), do: reject(:probes_required)
  defp validate_probes([]), do: reject(:probes_required)

  defp validate_probes(probes) when is_list(probes) and length(probes) > @max_probes,
    do: reject({:too_many_probes, length(probes), @max_probes})

  defp validate_probes(probes) when is_list(probes) do
    probes
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, []}, fn {probe, index}, {:ok, acc} ->
      case validate_probe(probe, index) do
        {:ok, valid} -> {:cont, {:ok, [valid | acc]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, valid} -> {:ok, Enum.reverse(valid)}
      error -> error
    end
  end

  defp validate_probes(other), do: reject({:invalid_probes, describe(other)})

  defp validate_probe(probe, index) when is_map(probe) and not is_struct(probe) do
    with :ok <- ensure_probe_keys(probe, index),
         {:ok, input} <- validate_input(probe, index),
         {:ok, expect} <- validate_expectation(Map.get(probe, :expect, :any_reply), index) do
      {:ok, %{input: input, expect: expect}}
    end
  end

  defp validate_probe(other, index), do: reject({:invalid_probe, index, describe(other)})

  defp ensure_probe_keys(probe, index) do
    case Map.keys(probe) -- @probe_keys do
      [] -> :ok
      unknown -> reject({:unknown_probe_keys, index, Enum.map(unknown, &describe/1)})
    end
  end

  # The input is the body of a signal sent to an agent that may live on another node, so
  # it has to survive `:erpc` and the manifest it is signed inside. Pids, refs, ports,
  # funs, and structs are none of those things.
  defp validate_input(probe, index) do
    case Map.fetch(probe, :input) do
      {:ok, input} ->
        if Beam.portable_term?(input),
          do: {:ok, input},
          else: reject({:probe_input_not_portable, index})

      :error ->
        reject({:missing_probe_input, index})
    end
  end

  defp validate_expectation(:any_reply, _index), do: {:ok, :any_reply}

  defp validate_expectation({:equals, value} = expect, index) do
    if Beam.portable_term?(value),
      do: {:ok, expect},
      else: reject({:expectation_not_portable, index})
  end

  defp validate_expectation({:contains, substring} = expect, index) do
    if is_binary(substring) and substring != "" and String.valid?(substring),
      do: {:ok, expect},
      else: reject({:invalid_contains_expectation, index, describe(substring)})
  end

  defp validate_expectation({:state_matches, key, value} = expect, index) do
    cond do
      not is_atom(key) or is_nil(key) -> reject({:invalid_state_key, index, describe(key)})
      not Beam.portable_term?(value) -> reject({:expectation_not_portable, index})
      true -> {:ok, expect}
    end
  end

  defp validate_expectation(other, index),
    do: reject({:unknown_expectation, index, describe(other)})

  defp validate_budget(ms) when is_integer(ms) and ms > 0 and ms <= @max_budget_ms, do: {:ok, ms}
  defp validate_budget(ms), do: reject({:invalid_budget_ms, describe(ms)})

  defp validate_latency(nil, _budget), do: {:ok, nil}

  defp validate_latency(ms, budget) when is_integer(ms) and ms > 0 and ms <= budget,
    do: {:ok, ms}

  defp validate_latency(ms, _budget), do: reject({:invalid_max_latency_ms, describe(ms)})

  defp validate_required(:all, _count), do: {:ok, :all}

  # `{:at_least, 0}` is a gate that gates nothing, which is worse than declaring none:
  # it reads like evidence in a registry entry while proving nothing.
  defp validate_required({:at_least, n} = required, count)
       when is_integer(n) and n >= 1 and n <= count,
       do: {:ok, required}

  defp validate_required(other, _count), do: reject({:invalid_required, describe(other)})

  defp validate_initial_state(state) when is_map(state) and not is_struct(state) do
    if Beam.portable_term?(state),
      do: {:ok, state},
      else: reject(:initial_state_not_portable)
  end

  defp validate_initial_state(other), do: reject({:invalid_initial_state, describe(other)})

  defp ensure_bounded(spec) do
    size = byte_size(:erlang.term_to_binary(spec))

    if size <= @max_spec_bytes,
      do: :ok,
      else: reject({:eval_spec_too_large, size, @max_spec_bytes})
  end

  defp reject(reason), do: {:error, {:invalid_eval_spec, reason}}

  # ## Execution

  defp execute(module, initial_state, spec) do
    id = evaluation_id(module)
    janitor = janitor(id)
    started = now_ms()

    try do
      case prepare(id, module, initial_state, spec) do
        :ok -> {:ok, report(module, spec, run_probes(id, spec, started), started)}
        {:error, reason} -> {:error, {:evaluation_unavailable, module, sanitize(reason)}}
      end
    rescue
      error -> {:error, {:evaluation_exception, module, Exception.message(error)}}
    catch
      kind, reason -> {:error, {:evaluation_failure, module, kind, describe(reason)}}
    after
      stop(id)
      dismiss(janitor)
    end
  end

  # The same guarantee `Ouroboros.Upgrade.Rollout.Probe.janitor/1` makes, for the same
  # reason: an evaluation runs under a caller's deadline, `after` does not run when a
  # deadline kills this process, and the agent started here is supervised rather than
  # linked to the evaluator — so it would keep its cluster-wide id and its helper instance
  # with nothing left to stop it. A separate process monitors this one and does.
  defp janitor(id) do
    owner = self()

    spawn(fn ->
      ref = Process.monitor(owner)

      receive do
        {:dismiss, ^owner} -> :ok
        {:DOWN, ^ref, :process, ^owner, :normal} -> :ok
        {:DOWN, ^ref, :process, ^owner, _killed} -> stop(id)
      end
    end)
  end

  defp dismiss(janitor), do: send(janitor, {:dismiss, self()})

  defp prepare(id, module, initial_state, spec) do
    with :ok <- ensure_loaded(module),
         {:ok, _pid} <- start(id, module, initial_state, spec),
         :ok <- await_visible(id, @visibility_retries) do
      :ok
    end
  end

  # The commit that just happened is supposed to have loaded this. Asking turns "the
  # rollout loaded nothing" into a named refusal rather than an UndefinedFunctionError
  # raised from inside an agent start.
  defp ensure_loaded(module) do
    case Code.ensure_loaded(module) do
      {:module, ^module} -> :ok
      {:error, reason} -> {:error, {:capability_not_loaded, reason}}
    end
  end

  # The spec seeds, the start spec decides: see `run/3` on why the merge is in this order.
  defp start(id, module, initial_state, spec) do
    seeded = Map.merge(spec.initial_state, initial_state)

    case Mesh.start_agent(id, agent: module, initial_state: seeded) do
      {:ok, pid} -> {:ok, pid}
      {:error, reason} -> {:error, {:evaluation_start_failed, reason}}
      other -> {:error, {:evaluation_start_failed, {:unexpected_result, describe(other)}}}
    end
  end

  # Mesh visibility is eventually consistent even for a local agent, so an evaluation
  # that asked once could report a healthy capability as missing.
  defp await_visible(_id, 0), do: {:error, :evaluation_agent_not_visible}

  defp await_visible(id, attempts) do
    if is_pid(Mesh.whereis(id)) do
      :ok
    else
      Process.sleep(@visibility_delay_ms)
      await_visible(id, attempts - 1)
    end
  end

  # The total budget is enforced between probes as well as inside them: a spec whose
  # first probe eats the whole budget records the rest as exhausted instead of running
  # them, so the deadline the artifact declared is the deadline the cluster observes.
  defp run_probes(id, spec, started) do
    spec.probes
    |> Enum.with_index()
    |> Enum.map_reduce(false, fn {probe, index}, exhausted? ->
      if exhausted? do
        {exhausted(index), true}
      else
        {run_probe(id, probe, index, spec, started), remaining(spec, started) <= 0}
      end
    end)
    |> elem(0)
  end

  defp run_probe(id, probe, index, spec, started) do
    case probe_timeout(spec, started) do
      timeout when timeout <= 0 -> exhausted(index)
      timeout -> Map.put(attempt(id, probe, timeout, spec), :index, index)
    end
  end

  defp attempt(id, probe, timeout, spec) do
    probe_started = now_ms()

    try do
      reply = exchange(id, probe.input, timeout)
      elapsed = elapsed_since(probe_started)
      Map.put(judge(id, probe, reply, elapsed, spec), :ms, elapsed)
    rescue
      error ->
        timed(failed({:probe_exception, Exception.message(error)}), probe_started)
    catch
      kind, reason ->
        timed(failed({:probe_failure, kind, describe(reason)}), probe_started)
    end
  end

  defp timed(result, started), do: Map.put(result, :ms, elapsed_since(started))

  defp exchange(id, input, timeout) do
    case Mesh.send_message(@source, id, input, timeout: timeout) do
      {:ok, agent} -> {:ok, agent}
      {:error, reason} -> {:error, reason}
      other -> {:error, {:unexpected_result, describe(other)}}
    end
  end

  defp judge(_id, _probe, {:error, reason}, _elapsed, _spec),
    do: failed({:message_failed, sanitize(reason)})

  defp judge(id, probe, {:ok, agent}, elapsed, spec) do
    if exceeded_latency?(elapsed, spec) do
      failed({:latency_exceeded, elapsed, spec.max_latency_ms})
    else
      check(id, probe.expect, agent)
    end
  end

  defp check(_id, :any_reply, _agent), do: passed()

  defp check(_id, {:equals, expected}, agent) do
    case reply_of(agent) do
      ^expected -> passed()
      actual -> failed({:not_equal, describe(actual)})
    end
  end

  defp check(_id, {:contains, substring}, agent) do
    if agent |> reply_of() |> render() |> String.contains?(substring) do
      passed()
    else
      failed({:not_contained, substring})
    end
  end

  defp check(id, {:state_matches, key, expected}, _agent) do
    case agent_state(id) do
      {:ok, state} ->
        case Map.fetch(state, key) do
          {:ok, ^expected} -> passed()
          {:ok, actual} -> failed({:state_mismatch, key, describe(actual)})
          :error -> failed({:state_key_absent, key})
        end

      {:error, reason} ->
        failed({:state_unreadable, sanitize(reason)})
    end
  end

  # An agent's answer is its post-exchange state, narrowed to the key it publishes
  # answers under when it has one. See the moduledoc: a capability that declares no
  # answer is compared against everything it holds, which is rarely what a spec means.
  defp reply_of(agent) do
    state = if is_struct(agent), do: Map.get(agent, :state), else: agent

    if is_map(state) and Map.has_key?(state, :last_answer) do
      Map.get(state, :last_answer)
    else
      state
    end
  end

  defp agent_state(id) do
    case Mesh.state(id) do
      {:ok, %{agent: %{state: state}}} when is_map(state) -> {:ok, state}
      {:ok, other} -> {:error, {:unexpected_agent_state, describe(other)}}
      {:error, reason} -> {:error, reason}
      other -> {:error, {:unexpected_agent_state, describe(other)}}
    end
  end

  defp exceeded_latency?(_elapsed, %{max_latency_ms: nil}), do: false
  defp exceeded_latency?(elapsed, %{max_latency_ms: max}), do: elapsed > max

  defp report(module, spec, results, started) do
    total_ms = elapsed_since(started)
    passed = Enum.count(results, &(&1.outcome == :passed))
    within_budget? = total_ms <= spec.budget_ms

    %{
      module: module,
      node: node(),
      probes: length(results),
      passed: passed,
      failed: length(results) - passed,
      total_ms: total_ms,
      budget_ms: spec.budget_ms,
      required: spec.required,
      within_budget?: within_budget?,
      satisfied?: within_budget? and required_met?(spec.required, passed, length(results)),
      results: results
    }
  end

  defp required_met?(:all, passed, count), do: passed == count
  defp required_met?({:at_least, n}, passed, _count), do: passed >= n

  defp passed, do: %{outcome: :passed, reason: nil}
  defp failed(reason), do: %{outcome: :failed, reason: reason}
  defp exhausted(index), do: %{index: index, ms: 0, outcome: :failed, reason: :budget_exhausted}

  # The total budget is the only deadline a call is cut at. `max_latency_ms` gates the
  # latency that was *observed*, which is a different statement: a probe that answers in
  # 300ms under a 50ms gate failed the gate, and reporting that is more useful than
  # reporting a timeout that hides whether the capability answered at all.
  defp probe_timeout(spec, started), do: remaining(spec, started)

  defp remaining(spec, started), do: spec.budget_ms - elapsed_since(started)

  defp stop(id) do
    Mesh.stop_agent(id)
    :ok
  rescue
    _error -> :ok
  catch
    _kind, _reason -> :ok
  end

  # The id must be unique in the namespace it joins, and that namespace is the whole
  # connected cluster: mesh groups propagate over `:pg`. `System.unique_integer/1` is
  # only VM-unique, and two peers evaluating the same module concurrently — the normal
  # case for a multi-node rollout — can collide, at which point both nodes' probes and
  # state reads route to whichever twin sorts first. `node()` is the cluster-unique
  # discriminator, so it is part of the id.
  defp evaluation_id(module) do
    "ouroboros-eval-" <>
      (module |> Atom.to_string() |> String.replace(".", "-")) <>
      "-" <>
      Atom.to_string(node()) <>
      "-" <> Integer.to_string(System.unique_integer([:positive]))
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
  defp elapsed_since(started), do: max(now_ms() - started, 0)

  # Everything below crosses `:erpc` into a coordinator that writes it to a durable
  # registry, so a reason keeps its shape only while it is portable and small.
  defp sanitize(reason) do
    if Beam.portable_term?(reason) and
         byte_size(:erlang.term_to_binary(reason)) <= @max_reason_bytes do
      reason
    else
      describe(reason)
    end
  end

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 120)
  defp render(term), do: inspect(term, limit: 200, printable_limit: 4_096)
end
