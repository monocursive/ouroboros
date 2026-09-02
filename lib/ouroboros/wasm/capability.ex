defmodule Ouroboros.Wasm.Capability do
  @moduledoc """
  The one wrapper agent every lane-W capability runs as.

  A lane-W capability introduces no BEAM module and no atom (docs/WASM.md D2). Its identity
  is the sha256 of its component bytes, and its runtime shape is *this* agent, shipped and
  protected, started with `initial_state` naming the component, the config the guest is
  initialized with, and a human name. `Ouroboros.Runtime.Manifesto` says a capability is "one
  Jido agent … started through `Mesh.start_agent/2` with an id, routing
  `ouroboros.agent.message` to an answering action"; this is that agent, once, for every
  component there will ever be.

  ## What it buys

  Because the state keys are the ones the BEAM lane already publishes — `:last_message`
  updated with the body, `:last_answer` holding the reply — `Ouroboros.Upgrade.Rollout.Probe`'s
  echo check and `Ouroboros.Upgrade.Rollout.Evaluation`'s whole expectation grammar
  (`:any_reply`, `{:equals, _}`, `{:contains, _}`, `{:state_matches, _, _}`) work against a
  wasm capability unchanged. Nothing in either module knows what a component is.

  ## Which instance is this agent's, and why nothing else may say

  The instance name is derived from the agent's **id alone** — `"wasm/" <> url-safe base64`,
  or `"wasm/h/" <> sha256` for an id too long to encode inside the pool's 256-byte bound.
  Two properties are load-bearing and neither is decoration. It is *injective*: url-safe
  base64 contains no `/`, so no two ids can encode to one name and the hashed form can never
  collide with the encoded one. And it is *underivable from anything a caller supplies* —
  `:name` is a label for a human, and putting it in an identity made
  `%{name: "n/mid", id: "tail"}` and `%{name: "n", id: "mid/tail"}` the same instance.

  A seeded `:instance` that is not this agent's derived name is **ignored**, not adopted.
  `Ouroboros.Mesh.start_agent/2` is remote-reachable and merges the caller's `initial_state`
  wholesale — Jido does not validate it against this schema — so trusting a seeded instance
  handed any caller a live instance belonging to some other agent, with that agent's config
  and that agent's accumulated guest state.

  ## Lazy, and repairable

  Nothing is loaded and nothing is instantiated until a message arrives. The first message
  resolves the component's path in `Ouroboros.Wasm.Store`, `load`s it into the helper (which
  recomputes the digest and refuses `sha_mismatch` before compiling anything), and stands an
  instance up under the bounds in `:limits` — or, when those are absent,
  `Ouroboros.Wasm.capability_limits/0`, the configured default. Later messages reuse that
  instance, which is what makes guest state observable across messages at all.

  A refusal that poisons the instance — `trapped`, `fuel_exhausted`, `deadline_exceeded`,
  `memory_limit`, and the `unknown_instance` that follows any of them — clears `:instance`, so
  the next message stands a fresh one up. So does a pool that is `:broken` or `:unavailable`:
  broken means the helper was hard-closed and killed, which is as much a fact about the
  instance as a trap is, and a probe landing in that window should not spend its one message
  discovering it. A `guest_error` is the guest *answering*, badly: it is recorded and the
  instance is kept, because nothing about it says the instance is untrustworthy.

  ## What the component says it is, and why that is not the same as what it is

  After the first message is answered, the wrapper asks the instance for its `describe` and
  keeps the result in `:describe` as `{:untrusted, {:ok, document}}` or
  `{:untrusted, {:invalid, reason}}` (contract C1; `__MODULE__.Describe` is the whole
  contract). It is fetched once, because it is a property of `:component` and that does not
  change; it is fetched *after* the message rather than at instantiate, because it is guest
  code that may trap and a trap before the message would have made a broken `describe` into
  a failed rollout probe.

  Nothing in it is an identity and nothing in it is trusted. The registry says what a
  capability is called and which bytes it is; this is what the bytes claim, bounded at
  4 KiB, closed to six keys, and tagged untrusted in the shape so no reader can forget.

  ## Nothing a guest does takes this agent down

  Every refusal — a missing component, a helper that was never built, a broken pipe, a trap,
  a guest that returns a string this node cannot decode — is recorded in `:error` and
  answered normally, and so is every *exception*: the state write is computed inside a
  `try` and is genuinely unconditional, because a wrapper whose bookkeeping can be skipped
  by a raise is one whose records cannot be trusted to be complete. That is not
  defensiveness for its own sake: the thing on the other end of this pipe is the thing lane
  W exists to contain, and a wrapper that crashes on a hostile component hands it a way to
  take down the process that was containing it. `:last_message` is written on every path,
  so an agent whose node never built a helper is still an agent that received a message.

  ## Wire data stays data

  The reply is JSON-decoded when it is JSON and kept as a string when it is not; the decoded
  form keeps **string** keys, and no atom is ever minted from anything a guest sent. A forged
  atom outlives the process that read it. Recorded refusals keep the shape peers match on
  (`reason.refusal`) and are otherwise bounded before they are stored: a failure term built
  out of a `GenServer.call/3` argument list carries the whole outbound message inside it.

  ## Nothing in `initial_state` is trusted, because nothing validates it

  `Ouroboros.Mesh.start_agent/2` is remote-reachable and merges a caller's `initial_state`
  wholesale; Jido does not check it against the schema above. So every key here that decides
  *what runs, where, and under what bounds* is validated where it is used, not where it is
  declared (F3):

    * **`:pool`** must resolve to a live local process that was started as
      `Ouroboros.Wasm.Pool` (or be the module name itself, this node's own singleton).
      Anything else is a recorded refusal and no request is sent. Untyped, it aimed this
      agent's `GenServer.call` at any process a starter could name, and the pool's
      `{:request, …}` tuple killed the process that received it.
    * **`:store_root`** is honoured only where `config :ouroboros, :wasm,
      allow_store_root_override: true` — this repository's test environment. Everywhere else
      the node's own store root is read, whatever the state says. Untyped, it ran unsigned,
      unregistered bytes out of any directory the BEAM user could read.
    * **`:limits`** is clamped element-wise to `Ouroboros.Wasm.capability_limits_max/0` and
      the clamp is recorded in `:error`. Untyped, a declaration was obeyed, so a starter
      wrote the helper's own maxima into it and got them.

  A separate hazard with the same shape: `Ouroboros.Upgrade.Rollout.Evaluation` merges a
  spec's `initial_state` *under* the start spec's, so the start spec wins the keys it names
  and only those, and a signed eval spec can seed any key it leaves out. The keys that decide
  what is being evaluated are **`:component`, `:config`, `:name`, `:limits`, `:pool` and
  `:store_root`**, and a caller that stands this agent up for evaluation should name all six.
  The validation above bounds what an unnamed one can cost; naming them is what makes the
  evaluation mean what it says. (`:instance` is the seventh and is safe unnamed, because a
  seeded instance is ignored above.)

  ## What is not here yet

  Jido exposes no terminate hook to an agent module — `Jido.Agent`'s callbacks are
  `on_before_cmd`, `on_after_cmd`, `signal_routes`, `checkpoint` and `restore`, and
  `Jido.AgentServer.terminate/2` delegates only to its own lifecycle module — so this agent
  cannot drop its instance on the way out. What covers it instead is ownership in the pool:
  `Ouroboros.Wasm.Pool.instantiate/6` is handed this agent's server pid, monitors it, and
  schedules the `drop` when it goes. That covers the stop, the crash, and the throwaway
  agents a rollout probe and an evaluation leave behind.

  What remains: an instance stood up while this node's mesh directory does not yet know the
  agent (`owner` resolves to `nil`) is unowned and is reclaimed by nothing here — the helper
  keeps it until the pool reconnects onto a fresh child, and W3's rollback drops explicitly.
  """

  alias Ouroboros.Wasm

  use Jido.Agent,
    name: "ouroboros_wasm_capability",
    description: "The static wrapper a WebAssembly capability component runs inside",
    schema: [
      # The capability's identity: the sha256 of the component bytes, lower-case hex. Not an
      # atom and not a module — that is the whole point of the lane (D2).
      component: [type: :string, default: ""],
      # Handed to the guest's `init` verbatim, once per instance.
      config: [type: :string, default: "{}"],
      # A label, for a log line. Deliberately not part of any identity — see the moduledoc.
      name: [type: :string, default: "capability"],
      # `%{fuel, memory_bytes, deadline_ms}`, all three or none, and each one clamped to this
      # node's `capability_limits_max` ceiling. See `limits/1`.
      limits: [type: :map, default: %{}],
      # The live instance's name in the helper, or nil when none is standing. Only ever
      # believed when it equals this agent's derived name.
      instance: [type: :any, default: nil],
      # The two keys the rollout machinery reads. See the moduledoc.
      last_message: [type: :any, default: nil],
      last_answer: [type: :any, default: nil],
      # What the component says it is, fetched once and kept: `{:untrusted, {:ok, document}}`
      # or `{:untrusted, {:invalid, reason}}`. The `:untrusted` tag is in the shape rather
      # than in a comment because every reader of this key is putting the value in front of
      # a model or an operator, and a value that has to be *remembered* to be untrusted is
      # one that eventually is not. See `__MODULE__.Describe`.
      describe: [type: :any, default: nil],
      messages_received: [type: :non_neg_integer, default: 0],
      error: [type: :any, default: nil],
      # Which pool to speak to, and which store to read. Both are the production values by
      # default and exist so a test can point one agent at its own helper and its own
      # directory without touching anything global. Both are **validated before they are
      # used**, because `Mesh.start_agent/2` is remote-reachable and Jido merges a caller's
      # `initial_state` without checking it against this schema (F3): `:pool` must name a
      # live local `Ouroboros.Wasm.Pool` process, and `:store_root` is honoured only on a node
      # whose config says `allow_store_root_override: true`.
      pool: [type: :any, default: Ouroboros.Wasm.Pool],
      store_root: [type: :any, default: nil]
    ],
    signal_routes: [
      {"ouroboros.agent.message", __MODULE__.HandleMessage}
    ]

  @doc "Every action this agent can execute. There is exactly one."
  def actions, do: super() ++ [__MODULE__.HandleMessage]

  @doc """
  The bounds an instance of this capability is stood up under.

  The deployed state's own `:limits` when it names all three, and
  `Ouroboros.Wasm.capability_limits/0` otherwise. A partial map falls back whole rather than
  being completed from the defaults: a bound nobody stated is not one this node gets to
  invent, and half of one is not a bound.

  Whichever of the two it is, **every value is clamped to this node's
  `Ouroboros.Wasm.capability_limits_max/0`** (F3). `:limits` arrives inside `initial_state`
  on the remote-reachable `Ouroboros.Mesh.start_agent/2`, and Jido does not validate
  `initial_state` against this agent's schema — so a declaration was simply obeyed, and a
  remote starter helped itself to the helper's own maxima on a node that had agreed to none
  of them. A clamp rather than a refusal because the node's ceiling is the node's answer to
  the question "how much may a capability have", and answering it is not the same as
  refusing to run the capability. What the clamp must never be is silent: `note/1` returns
  the fact, and `HandleMessage` records it in `:error` on every message.
  """
  @spec limits(map()) :: %{
          fuel: pos_integer(),
          memory_bytes: pos_integer(),
          deadline_ms: pos_integer()
        }
  def limits(state), do: clamp(declared(state), Wasm.capability_limits_max())

  @doc """
  What was clamped out of this capability's declared `:limits`, or `nil` when nothing was.

  Recorded in the agent's `:error` by `HandleMessage` so a declaration this node would not
  honour is visible where every other refusal is, rather than being obeyed quietly at a
  number nobody agreed to.
  """
  @spec note(map()) :: %{stage: :limits, reason: {:limits_clamped, map(), map()}} | nil
  def note(state) do
    declared = declared(state)
    effective = clamp(declared, Wasm.capability_limits_max())

    if effective == declared,
      do: nil,
      else: %{stage: :limits, reason: {:limits_clamped, declared, effective}}
  end

  defp declared(%{limits: %{fuel: fuel, memory_bytes: memory, deadline_ms: deadline}})
       when is_integer(fuel) and fuel > 0 and is_integer(memory) and memory > 0 and
              is_integer(deadline) and deadline > 0 do
    %{fuel: fuel, memory_bytes: memory, deadline_ms: deadline}
  end

  defp declared(_state), do: Wasm.capability_limits()

  defp clamp(limits, ceiling) do
    Map.new(limits, fn {key, value} -> {key, min(value, Map.fetch!(ceiling, key))} end)
  end

  defmodule Describe do
    @moduledoc """
    The contract a component's `describe` is read under, and the whole of it (contract C1).

    `describe` is the one place a component gets to say what it is in words a model will
    read. That makes it the lane's prompt-injection surface: the text is authored by the
    thing lane W exists to contain, it is not signed by anybody, and it reaches a model
    beside the node's own trusted facts. Two rules answer that, and both are here rather
    than at each reader so a second reader cannot get either wrong:

      * **Bounded before it is parsed.** The raw string is refused above
        #{4 * 1024} bytes without being decoded, and `name`, `version` and `summary` carry
        their own bounds inside it. A 4 KiB ceiling on the whole document is what makes
        "every capability's describe" a listing a context window can hold.
      * **Closed.** Six keys are read and every other key is dropped. A component cannot
        introduce a field into the shape a reader renders, which is the difference between
        untrusted *content* — which this is — and untrusted *structure*, which it is not.

    `name`, `version` and `world` are required, and `world` must be this node's: a
    component that runs here was admitted against `Ouroboros.Wasm.world/0` by the linker,
    so one claiming another world is describing something other than itself. `summary`,
    `input_schema` and `examples` are optional, and `examples` holds at most four.

    Nothing here is an identity. The registry says what a capability is called and which
    bytes it is; this says what the bytes claim about themselves, and `parse/1` returning
    `{:ok, document}` means only that the claim is well formed.
    """

    alias Ouroboros.Wasm
    alias Ouroboros.Wasm.Artifact

    @max_document_bytes 4 * 1024
    @max_summary_chars 200
    @max_version_bytes 64
    @max_examples 4

    # Deliberately not `Version.parse/1`: this is a string a component wrote, and the
    # question is whether it is shaped like a version, not whether this VM can build a
    # struct out of it. The struct would be one more thing minted from guest data.
    @semver ~r/\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\z/

    @type document :: %{
            name: String.t(),
            version: String.t(),
            world: String.t(),
            summary: String.t() | nil,
            input_schema: map() | nil,
            examples: [map()]
          }

    @doc "The largest `describe` this node will read. See the module doc."
    @spec max_document_bytes() :: pos_integer()
    def max_document_bytes, do: @max_document_bytes

    @doc """
    One raw `describe` string, validated against C1.

    Total: every refusal is `{:invalid, reason}` and nothing raises, because the caller is
    a wrapper whose whole job is to survive a hostile component. The reason names the rule
    that was broken and never quotes the value that broke it — a refusal that echoes guest
    prose back into a log is the same injection with a different destination.
    """
    @spec parse(term()) :: {:ok, document()} | {:invalid, term()}
    def parse(raw) when is_binary(raw) do
      if byte_size(raw) > @max_document_bytes do
        {:invalid, {:oversize_describe, byte_size(raw), @max_document_bytes}}
      else
        decode(raw)
      end
    end

    def parse(_raw), do: {:invalid, :describe_not_a_string}

    defp decode(raw) do
      case JSON.decode(raw) do
        {:ok, document} when is_map(document) -> validate(document)
        {:ok, _other} -> {:invalid, :describe_not_an_object}
        {:error, _reason} -> {:invalid, :describe_not_json}
      end
    end

    defp validate(document) do
      with {:ok, name} <- name(Map.get(document, "name")),
           {:ok, version} <- version(Map.get(document, "version")),
           {:ok, world} <- world(Map.get(document, "world")),
           {:ok, summary} <- summary(Map.get(document, "summary")),
           {:ok, schema} <- input_schema(Map.get(document, "input_schema")),
           {:ok, examples} <- examples(Map.get(document, "examples")) do
        # Built key by key, so every key not named above is dropped rather than carried.
        {:ok,
         %{
           name: name,
           version: version,
           world: world,
           summary: summary,
           input_schema: schema,
           examples: examples
         }}
      end
    end

    # The same charset a rollout name is held to. Not because they must be the same name —
    # this one is the component's claim and that one is the registry's fact — but because a
    # name a model reads should be a name, and this is the narrowest definition of one this
    # runtime already has.
    defp name(value) do
      if Artifact.name?(value), do: {:ok, value}, else: {:invalid, :invalid_describe_name}
    end

    defp version(value) when is_binary(value) and byte_size(value) <= @max_version_bytes do
      if Regex.match?(@semver, value),
        do: {:ok, value},
        else: {:invalid, :invalid_describe_version}
    end

    defp version(_value), do: {:invalid, :invalid_describe_version}

    defp world(value) when is_binary(value) do
      if value == Wasm.world(),
        do: {:ok, value},
        else: {:invalid, :describe_world_mismatch}
    end

    defp world(_value), do: {:invalid, :describe_world_mismatch}

    defp summary(nil), do: {:ok, nil}

    # Plain text, checked rather than assumed: a control character in a summary is how a
    # component reaches a terminal renderer, and a lone surrogate is how it reaches an
    # encoder that will not have it. Both are refusals of the whole document, because a
    # summary this node would have to repair is one whose author was not writing prose.
    defp summary(value) when is_binary(value) do
      cond do
        not String.valid?(value) ->
          {:invalid, :invalid_describe_summary}

        String.length(value) > @max_summary_chars ->
          {:invalid, :oversize_describe_summary}

        String.match?(value, ~r/[\x00-\x08\x0b-\x1f\x7f]/) ->
          {:invalid, :invalid_describe_summary}

        true ->
          {:ok, value}
      end
    end

    defp summary(_value), do: {:invalid, :invalid_describe_summary}

    # Absent means "any JSON", per C1. Present and not an object is a broken claim, not a
    # permissive one: this node does not get to guess which the author meant.
    defp input_schema(nil), do: {:ok, nil}
    defp input_schema(value) when is_map(value), do: {:ok, value}
    defp input_schema(_value), do: {:invalid, :invalid_describe_input_schema}

    defp examples(nil), do: {:ok, []}

    defp examples(value) when is_list(value) do
      cond do
        length(value) > @max_examples ->
          {:invalid, {:too_many_describe_examples, length(value), @max_examples}}

        not Enum.all?(value, &(is_map(&1) and not is_struct(&1))) ->
          {:invalid, :invalid_describe_example}

        true ->
          {:ok, Enum.map(value, &Map.take(&1, ["message", "reply"]))}
      end
    end

    defp examples(_value), do: {:invalid, :invalid_describe_examples}
  end

  defmodule HandleMessage do
    @moduledoc """
    One mesh message into the component, one reply back into agent state.

    The state write is a `ReplaceState` rather than a returned map because Jido merges an
    action's result into agent state *deeply* (`Jido.Agent.State.merge/2`), and `:last_answer`
    is whatever a guest decided to send: deep-merging two replies would leave keys from the
    previous one standing inside the current one, which is a lie about what the capability
    just answered. `Ouroboros.Agent.Worker` dodges the same merge by choosing data shapes;
    this action cannot choose the guest's.
    """

    alias Jido.Agent.StateOp
    alias Ouroboros.Mesh
    alias Ouroboros.Wasm
    alias Ouroboros.Wasm.Capability
    alias Ouroboros.Wasm.Pool
    alias Ouroboros.Wasm.Store

    use Jido.Action,
      name: "wasm_capability_handle_message",
      description: "Forward a mesh message to a WebAssembly capability instance",
      schema: [
        from: [type: :string, required: true],
        body: [type: :any, required: true],
        correlation_id: [type: :string, required: true],
        causation_id: [type: :any, default: nil]
      ]

    # The refusals that mean the helper no longer holds this instance. Every one of them
    # leaves the name free, so the next message stands a fresh instance up under it rather
    # than having to invent a new one.
    @poisoning ~w(trapped fuel_exhausted deadline_exceeded memory_limit unknown_instance)

    # The refusals a `describe` may earn that are *the component's own doing*, and are
    # therefore recorded as its description rather than retried. `unknown_instance` is
    # deliberately absent even though it poisons: it means the helper no longer holds the
    # instance, which is a fact about the helper's table and not about the bytes.
    @describe_faults ~w(guest_error trapped fuel_exhausted deadline_exceeded memory_limit
                        oversize_result unknown_export)

    # A pool that is broken has already hard-closed and killed its child, and one that is
    # unavailable never had one: either way the helper's table is gone, which is a fact about
    # the instance and not only about the transport. `:timeout` is deliberately *not* here —
    # a request that timed out in the queue was never sent, so it says nothing.
    @helper_gone [:broken, :unavailable]

    # The longest instance name the pool will send. Ids that do not encode inside it are
    # hashed rather than truncated: a cut prefix is not an identity.
    @max_instance_bytes 256
    @prefix "wasm/"
    @hashed_prefix "wasm/h/"

    # What a recorded refusal may cost. The first mirrors the pool's own cap on helper prose;
    # the second is per key of a malformed result frame, whose keys are somebody else's
    # strings and are bounded by bytes rather than by how many of them there are.
    @max_reason_bytes 2_048
    @max_key_bytes 128

    @impl true
    def run(params, %{agent: agent}) do
      state = agent.state

      message = %{
        from: params.from,
        body: params.body,
        correlation_id: params.correlation_id,
        causation_id: params.causation_id
      }

      # Unconditional: the whole exchange, the name derivation and the owner lookup included,
      # is inside this `try`, so there is no input for which this agent records nothing.
      outcome =
        try do
          exchange(state, agent, params.body)
        rescue
          error -> failed(:exception, Exception.message(error))
        catch
          kind, reason -> failed(:exception, "#{kind}: #{describe(reason)}")
        end

      changes =
        Map.merge(outcome, %{
          last_message: message,
          messages_received: next_message_count(state)
        })

      {:ok, %{}, [%StateOp.ReplaceState{state: Map.merge(state, changes)}]}
    end

    # `initial_state` crosses a remote-reachable boundary and Jido deliberately merges it
    # without applying this agent's schema. Bookkeeping must therefore tolerate the same
    # hostile seed as every authority-bearing field below: an invalid counter means no
    # messages have been counted, not an arithmetic exception outside `run/2`'s rescue.
    defp next_message_count(state) do
      case Map.get(state, :messages_received) do
        count when is_integer(count) and count >= 0 -> count + 1
        _invalid_or_absent -> 1
      end
    end

    # Everything below answers with the three keys the exchange decides — `:instance`,
    # `:last_answer`, `:error`. A refusal is a recorded fact about this message, not a fault
    # of the agent holding it.
    defp exchange(state, agent, body) do
      name = instance_name(agent)
      # A declaration this node clamped is carried through the whole exchange and recorded
      # even when everything else succeeds, so it is visible on *every* message rather than
      # only on the one that stood the instance up.
      note = Capability.note(state)

      with {:ok, pool} <- pool_of(state),
           {:ok, payload} <- encode(body),
           {:ok, instance} <- stand_up(state, pool, name, owner_of(agent)) do
        pool |> deliver(instance, payload, note) |> describe(state, pool)
      else
        {:refused, stage, reason} ->
          %{instance: nil, last_answer: nil, error: refusal(stage, reason)}
      end
    end

    # `describe` is fetched once per agent, on the message path, and **after** the message
    # has been answered. Both halves of that are decisions (docs/WASM.md D17).
    #
    # *After*, because `describe` is the guest's code like any other and may trap. A trap
    # poisons the instance, and a describe that ran first would have turned a component with
    # a broken `describe` into a component whose every first message fails — including the
    # one message `Ouroboros.Upgrade.Rollout.Probe` spends deciding whether a deploy is
    # healthy. Answering first means a bad `describe` costs the description and nothing else.
    #
    # *Once*, because the answer is a property of the component bytes, and `:component` does
    # not change for the life of an agent. So the second message pays nothing, and a live
    # capability that has never been messaged is honestly `nil` rather than described by
    # something this node made up.
    #
    # It never touches `:last_answer` or `:error`: those record what the *message* did, and
    # a failure to fetch metadata is not a failure of the message that happened to trigger it.
    defp describe(outcome, %{describe: recorded}, _pool) when not is_nil(recorded), do: outcome

    # No live instance to ask — the message poisoned it, or the helper broke. Nothing is
    # recorded, so the next message asks again: an absent description must not be cached as
    # a verdict about the component.
    defp describe(%{instance: nil} = outcome, _state, _pool), do: outcome

    defp describe(%{instance: instance} = outcome, _state, pool) do
      case Pool.describe(instance, pool) do
        {:ok, %{"payload" => payload}} when is_binary(payload) ->
          Map.put(outcome, :describe, {:untrusted, Capability.Describe.parse(payload)})

        {:ok, other} ->
          Map.put(outcome, :describe, {:untrusted, {:invalid, {:malformed_result, keys(other)}}})

        # The guest answered, badly, or took itself down answering. Both are facts about the
        # component and are recorded as its description — there is nothing to retry, because
        # the same bytes will answer the same way. A poisoning refusal additionally frees the
        # name, exactly as it does on the message path.
        {:error, %{refusal: named} = reason} when named in @describe_faults ->
          outcome
          |> Map.put(:describe, {:untrusted, {:invalid, refusal(:describe, reason)}})
          |> Map.put(:instance, if(named in @poisoning, do: nil, else: instance))

        # Everything else — a helper that broke, a queue that was full, an instance the
        # helper no longer holds, a caller past its own deadline — says nothing about the
        # component. Nothing is recorded and the next message asks again, because caching a
        # transport fault as "this component cannot describe itself" is a claim about the
        # wrong party.
        {:error, _transport} ->
          outcome
      end
    end

    # Which process this agent may aim a `GenServer.call` at, and the answer is: one that is
    # actually a `Ouroboros.Wasm.Pool` on this node (F3).
    #
    # `:pool` is `type: :any` in the schema and arrives inside `initial_state` on the
    # remote-reachable `Mesh.start_agent/2`, which Jido merges without checking it against
    # that schema. Before this, whatever a starter wrote was handed straight to
    # `GenServer.call/3`: a registered name, and the pool's own `{:request, …}` tuple was
    # delivered to somebody else's process — enough to kill an `Agent` on a `function_clause`
    # — or a pid, with the same effect. So the value is *resolved* and then *identified*:
    # `:proc_lib.translate_initial_call/1` names the module a live process was started as,
    # which is the one fact about it a caller cannot forge from the outside.
    #
    # `Ouroboros.Wasm.Pool` itself is the exception and is always allowed. It is this node's
    # own singleton and it is lazy: a node where it is not running answers `:unavailable`
    # through the ordinary path, and turning that into a start-state refusal would be a
    # different (and less honest) message about a pool nobody chose.
    defp pool_of(%{pool: Pool}), do: {:ok, Pool}

    defp pool_of(%{pool: pool}) do
      case GenServer.whereis(pool) do
        pid when is_pid(pid) and node(pid) == node() ->
          if :proc_lib.translate_initial_call(pid) == {Pool, :init, 1},
            do: {:ok, pid},
            else: {:refused, :pool, {:pool_not_a_wasm_pool, describe(pool)}}

        _remote_or_absent ->
          {:refused, :pool, {:pool_not_a_wasm_pool, describe(pool)}}
      end
    rescue
      # `GenServer.whereis/1` raises on a term that is not a server reference at all, which
      # is exactly what an arbitrary `initial_state` value may be.
      _error -> {:refused, :pool, {:pool_not_a_wasm_pool, describe(pool)}}
    end

    defp deliver(pool, instance, payload, note) do
      case Pool.call(instance, "handle-message", payload, pool) do
        {:ok, %{"payload" => reply}} when is_binary(reply) ->
          %{instance: instance, last_answer: decode(reply), error: note}

        {:ok, other} ->
          # The helper broke its own result contract. The instance is still live as far as it
          # is concerned, so it is kept and the frame is recorded by shape.
          %{
            instance: instance,
            last_answer: nil,
            error: refusal(:call, {:malformed_result, keys(other)})
          }

        # The guest answered with its own `err`. That is an answer: it is what the capability
        # said, the instance stays live, and both facts are recorded.
        {:error, %{refusal: "guest_error", message: message} = reason} ->
          %{instance: instance, last_answer: message, error: refusal(:call, reason)}

        {:error, %{refusal: named} = reason} when named in @poisoning ->
          %{instance: nil, last_answer: nil, error: refusal(:call, reason)}

        {:error, reason} when reason in @helper_gone ->
          %{instance: nil, last_answer: nil, error: refusal(:call, reason)}

        {:error, reason} ->
          # Every other refusal — another named one, a full queue, a caller that outlived its
          # own deadline — says nothing about the instance, so it is kept.
          %{instance: instance, last_answer: nil, error: refusal(:call, reason)}
      end
    end

    # Idempotent, and only for this agent's own instance. A `:instance` that is anything else
    # is somebody else's name or a stale one, and is stood over rather than adopted — nothing
    # about the seeded value is recorded, because there is nothing about it worth keeping.
    defp stand_up(%{instance: instance}, _pool, name, _owner) when instance == name,
      do: {:ok, name}

    defp stand_up(state, pool, name, owner) do
      with {:ok, path} <- store_path(state),
           :ok <- load(state, pool, path),
           :ok <- instantiate(state, pool, name, owner) do
        {:ok, name}
      end
    end

    defp store_path(state) do
      case Store.path(state.component, store_opts(state)) do
        {:ok, path} -> {:ok, path}
        {:error, reason} -> {:refused, :store, reason}
      end
    end

    # A seeded `:store_root` names which bytes this capability runs, and it arrives on a
    # remote-reachable start surface, so it is honoured only where the node's own config says
    # so — this repository's test environment, and nowhere else by default (F3). Everywhere
    # else the node's own store root is used and the seeded value is simply not read: it is
    # not a refusal, because the agent is perfectly runnable from the store it is supposed to
    # read from.
    defp store_opts(%{store_root: root}) when is_binary(root) and root != "" do
      if Wasm.allow_store_root_override?(), do: [root: root], else: []
    end

    defp store_opts(_state), do: []

    # `load` is idempotent helper-side: a component already in its cache is reported as
    # cached rather than compiled again.
    defp load(state, pool, path) do
      case Pool.load(state.component, path, pool) do
        {:ok, _report} -> :ok
        {:error, reason} -> {:refused, :load, reason}
      end
    end

    defp instantiate(state, pool, name, owner) do
      case stand(state, pool, name, owner) do
        {:ok, _result} ->
          :ok

        # A predecessor of this agent left an instance standing under this name — an agent
        # that died before the pool's reclaim `drop` went out, or one this pool never owned.
        # The name is derived from this agent's id and belongs to it; take it back rather
        # than refusing every message forever.
        {:error, %{refusal: "instance_exists"}} ->
          _ = Pool.drop(name, pool)

          case stand(state, pool, name, owner) do
            {:ok, _result} -> :ok
            {:error, reason} -> {:refused, :instantiate, reason}
          end

        {:error, reason} ->
          {:refused, :instantiate, reason}
      end
    end

    defp stand(state, pool, name, owner) do
      Pool.instantiate(
        name,
        state.component,
        state.config,
        Capability.limits(state),
        pool,
        owner: owner
      )
    end

    # The body crosses into the guest as JSON. A term that cannot be encoded is this node's
    # problem, not the guest's, and is refused before the helper is touched.
    defp encode(body) do
      {:ok, JSON.encode!(body)}
    rescue
      error -> {:refused, :encode, {:unencodable_body, Exception.message(error)}}
    end

    # A reply that is JSON becomes the term it encodes, with string keys; one that is not
    # stays the string it was. Neither path mints an atom.
    defp decode(reply) do
      case JSON.decode(reply) do
        {:ok, value} -> value
        {:error, _reason} -> reply
      end
    end

    defp failed(stage, reason),
      do: %{instance: nil, last_answer: nil, error: refusal(stage, reason)}

    # A refusal the pool already bounded keeps its shape: peers match on `reason.refusal`,
    # and `Ouroboros.Wasm.Pool` caps the prose inside it.
    defp refusal(stage, %{refusal: named} = reason) when is_binary(named),
      do: %{stage: stage, reason: reason}

    defp refusal(stage, reason), do: %{stage: stage, reason: sanitize(reason)}

    # Everything else is a term built out of somebody's arguments, and some of those
    # arguments are this message: a `GenServer.call/3` that exits carries its whole request
    # in the exit reason, which for a `call` is the entire outbound payload. Small terms keep
    # their shape because a named tuple is worth matching on; large ones become bounded text.
    # `external_size/1` measures without building the binary, so measuring a megabyte costs
    # nothing.
    defp sanitize(reason) do
      if :erlang.external_size(reason) <= @max_reason_bytes,
        do: reason,
        else: describe(reason)
    end

    defp describe(term),
      do: term |> inspect(limit: 10, printable_limit: 256) |> bounded(@max_reason_bytes)

    # A malformed frame is recorded by shape, not by content: the keys are helper-supplied
    # strings, so they are bounded by bytes as well as counted.
    defp keys(map) when is_map(map) do
      map
      |> Map.keys()
      |> Enum.filter(&is_binary/1)
      |> Enum.take(8)
      |> Enum.map(&bounded(&1, @max_key_bytes))
    end

    defp bounded(text, cap) when byte_size(text) <= cap, do: text
    defp bounded(text, cap), do: valid_prefix(binary_part(text, 0, cap)) <> "…"

    # The cut is by bytes and then walked back to a whole character, because a string half a
    # codepoint long is one no surface downstream can encode. Same walk as the pool's.
    defp valid_prefix(binary) do
      cond do
        String.valid?(binary) -> binary
        byte_size(binary) == 0 -> binary
        true -> binary |> binary_part(0, byte_size(binary) - 1) |> valid_prefix()
      end
    end

    # Derived from the agent's id and from nothing else. `Ouroboros.Mesh` makes an id unique
    # across the cluster — `:global.trans/2` around a `whereis` check — and url-safe base64
    # is injective and contains no `/`, so no two agents can name one instance and no encoded
    # name can be mistaken for a hashed one. See the module doc for what putting `:name` in
    # here cost.
    defp instance_name(agent) do
      id = identity(agent)
      encoded = @prefix <> Base.url_encode64(id, padding: false)

      if byte_size(encoded) <= @max_instance_bytes do
        encoded
      else
        @hashed_prefix <> (:sha256 |> :crypto.hash(id) |> Base.encode16(case: :lower))
      end
    end

    defp identity(%{id: id}) when is_binary(id), do: id
    defp identity(agent), do: inspect(Map.get(agent, :id))

    # The agent-server pid, asked for by id rather than taken from `self()`: Jido may run
    # this action in a task it spawned for the signal call, so `self()` is not the agent. The
    # *local* member specifically — the instance lives in this node's helper, so a remote
    # twin's pid would be the wrong thing to monitor. `nil` leaves the instance unowned,
    # which the module doc records as the one case nothing here reclaims.
    defp owner_of(agent) do
      agent
      |> identity()
      |> Mesh.members()
      |> Enum.find(&(node(&1) == node()))
    end
  end
end
