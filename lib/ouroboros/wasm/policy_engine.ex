defmodule Ouroboros.Wasm.PolicyEngine do
  @moduledoc """
  A permission engine that can ask a signed WebAssembly component (docs/WASM.md §8.2, D20).

  Named in `config :ouroboros, :permissions_engine`, it stands exactly where
  `Ouroboros.Control.Permissions` stood and delegates every call to it. The one thing it adds
  is this: when the rules said *nothing* — `{:ask, :no_rule}`, which is most calls — it asks a
  policy component, and lets that component **narrow** the answer.

      evaluate(request)
        └─ Control.Permissions.evaluate(request)
             ├─ {:allow, ref} / {:deny, ref} / {:ask, <anything but :no_rule>} → returned as is
             └─ {:ask, :no_rule} → the active policy component's `evaluate`

  `record/2` and `suggest/1` are `Control.Permissions`' unchanged, because a decision a human
  made and a rule an operator would write are not this module's business.

  ## What a component may decide, and what it may not (D20)

  | verdict | what happens |
  |---|---|
  | `deny` | **stands.** The call is refused and the component's rule is the stated reason. |
  | `ask` | stands. It is the same question the node was already going to ask. |
  | `allow` | honoured **only** for a tool named in `config :ouroboros, :policy_allowable_tools`, which is empty by default. Otherwise it is read as `ask`. |

  Everything else is `ask`: a component that traps, one that misses its deadline, one whose
  bytes will not link, one this node cannot load, a verdict that is not JSON, a `decision` that
  is not one of the three words, a request too large to hand over whole, and the case where no
  policy is configured at all. **There is no failure mode of this module that produces an
  `allow`**, which is the whole posture: a policy component narrows until an operator widens it.

  The `allow` list exists because the engine reaches a component for *every* call the rules did
  not decide. A component whose `allow` were honoured unconditionally would be a blanket
  approval channel with a signature on it — and the point of lane W is that a signature is
  provenance, not trust (D5). An operator who wants a component to resolve `read` calls says so
  by naming `read`.

  ## Determinism, and why it is structural

  A policy component decides permissions, so the same request must yield the same verdict on
  every node, forever. That is not asked of an author as discipline: `ouroboros:policy@0.1.0`
  imports exactly one function, `log`, so a component in it has no clock, no randomness, no
  filesystem and no network to be nondeterministic *with* (D21). Instance state is the one thing
  left, and it is the author's to hold or not; `test/wasm/policy_engine_test.exs` proves the same
  request answers the same on two separate instances of one component.

  ## The request a component sees

  The JSON form of the request `Control.Permissions` already normalised — the tool, the mode,
  the command and paths and domains under `input`, the principal, the workspace root, and the
  context keys — with every credential-shaped value redacted by `Jido.Harness.Redaction`, the
  same redaction the durable session projection uses.

  **It is never truncated.** A document that would exceed #{64 * 1024} bytes is not sent at all
  and the engine answers `ask`: a policy shown the first four kilobytes of a command line is a
  policy an attacker pads past, and a partial view is worse than no view because it produces a
  confident wrong answer. Non-scalar `context` values are dropped rather than serialised, and
  the keys that were dropped are named in `context_dropped` so a careful policy can ask rather
  than assume.

  ## One instance per policy sha

  The component is instantiated once, under a name derived from its sha, and every request after
  that reaches the same instance — the same lifecycle a deployed capability has, under the same
  `Ouroboros.Wasm.capability_limits/0` budget and the same helper eviction rules. A refusal of
  any kind drops the instance and the next request stands a fresh one up, because a guest that
  trapped has been stopped somewhere it did not choose and there is no honest way to keep asking
  it.

  ## What is written down

  Every decision this module *makes* — an honoured `deny` or `allow` — is recorded through
  `Control.Permissions.record/2` as `actor: :classifier`, the slot the answer type has always
  reserved. The entry's `rule_ref` carries the component's sha and the rule string, so the
  ledger says which bytes decided and what they said. A verdict that degraded to `ask` writes
  nothing: the node is about to ask a human, and that answer is recorded where every human
  answer is.

  Everything a component says about itself or about a call is **untrusted text**. The rule is
  bounded at #{200} characters, stripped of every control and format character, and labelled
  `[untrusted policy component]` wherever it reaches a model or a person.

  ## Where the node-local authorities come from

  The register, the store and the helper pool are this node's own, under their own names, and
  that is what production wants. `config :ouroboros, :wasm_policy_opts` names them instead — a
  keyword list of `:registry`, `:store_root` and `:pool` — for the same reason
  `Control.Permissions` lets `:permissions_ledger` be named: it is what lets a test point this
  engine at a register it controls and a store it wrote, which is the only way to observe a
  deny standing, an allow degrading and a misconfigured policy going inert. `:store_root` is
  honoured only where `Ouroboros.Wasm.allow_store_root_override?/0` is true, exactly as
  `Ouroboros.Wasm.Capability`'s is, because a directory name that decides which unsigned bytes
  get instantiated is not a setting.

  ## Scope

  Every seam reads `:permissions_engine` (W18, D27): the native loop
  (`Ouroboros.Provider.Native.Permissions`), the interactive plane's external approvals
  (`Ouroboros.Interactive.Task.Approvals`), and the ACP lane through
  `Ouroboros.Control.Permissions.Seam` — which is both the `session/request_permission` a vendor
  process sends and the `fs/write_text_file` and `terminal/create` an ACP agent asks this runtime
  to perform. A node that names this module has a policy on every lane a permission question can
  arrive on, and `test/wasm/policy_acp_test.exs` is the ACP half of that end to end. The seam
  carries this module's answer and narrows on any failure of its own, so nothing there can turn
  a verdict into more than what `settle/6` already honoured.
  """

  require Logger

  alias Jido.Harness.Redaction
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Control.Permissions.Request
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.{Artifact, Pool, Rollout, Store, Verifier}

  # The whole document, encoded. A request larger than this is not sent — see the moduledoc on
  # why nothing here truncates. Sized to hold a realistic `bash` command line, sixty-four
  # canonical paths and a context map with room to spare.
  @max_request_bytes 64 * 1024

  # A component's rule string, in characters. The same bound the SDK clips to and the same one
  # `ouro wasm policy` prints against, so an author sees the number in three places.
  @max_rule_chars 200

  # How many `context` keys travel. The context is content-minimised by contract and this is a
  # bound on somebody else's map, not a promise about what is in it.
  @max_context_keys 32

  # The label every string a component authored wears wherever a model or a person reads it.
  @untrusted "[untrusted policy component]"

  # What a redacted value is replaced with. `Jido.Harness.Redaction`'s word, so one grep finds
  # every redaction this runtime performs.
  @redacted "[REDACTED]"

  # A key whose value is a credential whatever the value looks like. `Jido.Harness.Redaction`'s
  # pattern, applied to a key with every run of non-alphanumerics folded to `_`.
  @credential_key ~r/(^|_)(authorization|credential|password|secret|token|api_?key)($|_)/i

  # Token shapes worth recognising in a *value*, most specific first.
  #
  # `Bearer` stops at a quote and a bracket as well as at whitespace, which the harness's own
  # pattern does not: `-H "Authorization: Bearer abc"` had its closing quote eaten, and a
  # document that loses a quote is a document a component reads differently from the one this
  # node built.
  #
  # The `NAME=value` and `NAME: value` rules are what catch a credential passed on a command
  # line — `AWS_SECRET_ACCESS_KEY=…`, `X-Api-Key: …` — where the name is the only thing that
  # says the value is a secret. The name is kept; only the value goes.
  @token_shapes [
    # A PEM block, terminated or not. The terminated form first, so an unterminated one is not
    # matched by a lazy `.*?` that stops immediately and leaves the key body behind.
    {~r/-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----/su,
     "-----BEGIN PRIVATE KEY-----[REDACTED]-----END PRIVATE KEY-----"},
    # The unterminated form, which must not re-match what the terminated one just wrote.
    {~r/-----BEGIN[A-Z ]*PRIVATE KEY-----(?!\[REDACTED\]).*/su,
     "-----BEGIN PRIVATE KEY-----[REDACTED]"},
    {~r/\bBearer\s+[^\s,;"'\)\]}]+/i, "Bearer [REDACTED]"},
    {~r/\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,})\b/,
     "[REDACTED]"},
    {~r/\bsk-[A-Za-z0-9_-]{8,}/, "[REDACTED]"},
    {~r/\bgithub_pat_[A-Za-z0-9_]{20,}/, "[REDACTED]"},
    {~r/\bgh[pousr]_[A-Za-z0-9]{16,}/, "[REDACTED]"},
    {~r/\bxox[abposr]-[A-Za-z0-9-]{8,}/, "[REDACTED]"},
    # `NAME=value` and `NAME: value` where the name is the only thing saying the value is a
    # secret. The name and its separator are kept verbatim — a rewritten separator is a
    # different command line — and a value a pass above already redacted is left alone.
    {~r/((?:^|[\s"'({\[,;])[A-Za-z0-9_.-]*(?:AUTHORIZATION|CREDENTIALS?|PASSWORD|SECRET|TOKEN|API_?KEY)[A-Za-z0-9_.-]*)(\s*[:=]\s*)("?)(?!(?:Bearer\s+)?\[REDACTED\])[^\s"'&;]+/i,
     "\\1\\2\\3[REDACTED]"}
  ]

  # Where this process caches the node's own environment secrets. Per process rather than
  # global: this runs on the permission path and `System.get_env/0` is not free.
  @secrets_key {__MODULE__, :environment_secrets}

  # The three words a verdict may carry. Anything else is `ask`.
  @decisions %{"allow" => :allow, "deny" => :deny, "ask" => :ask}

  # The whole verdict document, in bytes, refused before it is decoded. A verdict is two keys
  # and a sentence; a kibibyte is five times the largest one this grammar admits.
  @max_verdict_bytes 1024

  # Exactly the keys a verdict has. Closed, and checked as a sorted list, which is also what
  # refuses a repeated key — `["decision", "decision"]` is not this.
  @verdict_keys ["decision", "rule"]

  # The instance name a policy component is held under: derived from the sha, so one component
  # is one instance whichever process asks and a second concurrent caller finds it already up.
  @instance_prefix "wasm/policy/"

  # How long one *decision* may take, end to end, including a re-instantiate. See `evaluate/1`.
  @default_decision_timeout_ms 5_000
  @max_decision_timeout_ms 60_000

  # Bounds on a signed policy eval spec, matching `Ouroboros.Upgrade.Rollout.Evaluation`'s in
  # spirit: a spec is signed, replicated to every target and stored in a durable registry, so an
  # unbounded spec is an unbounded manifest.
  @max_cases 20
  @max_spec_bytes 16_384
  @default_case_budget_ms 10_000
  @max_case_budget_ms 120_000

  @type verdict :: :allow | :deny | :ask

  @doc """
  Decides one tool call, consulting the active policy component only where the rules did not.

  Never raises and never returns anything but `Control.Permissions`' three shapes. Every failure
  in the component path degrades to the answer the delegate already gave, which for the only
  branch that reaches a component is `{:ask, :no_rule}`.
  """
  @spec evaluate(map() | keyword()) :: Permissions.outcome()
  def evaluate(request) do
    case Permissions.evaluate(request) do
      {:ask, :no_rule} = asked -> consult(request, asked)
      decided -> decided
    end
  rescue
    error ->
      Logger.warning("wasm policy engine failed: #{Exception.message(error)}")
      {:ask, :authority_unavailable}
  catch
    _kind, _reason -> {:ask, :authority_unavailable}
  end

  @doc "The delegate's, unchanged: a human's answer is not this module's to interpret."
  @spec record(String.t(), map()) :: :ok | {:error, term()}
  defdelegate record(decision_id, answer), to: Permissions

  @doc "The delegate's, unchanged: the rule language is `Control.Permissions`'."
  @spec suggest(map() | keyword()) :: String.t() | nil
  defdelegate suggest(request), to: Permissions

  @doc """
  The name of the policy component this node consults, or `nil`.

  `nil` — the default — makes this engine exactly `Control.Permissions` with an extra function
  call, which is the posture a node that has not been given a policy should have.
  """
  @spec configured_policy() :: String.t() | nil
  def configured_policy do
    case Application.get_env(:ouroboros, :wasm_policy) do
      name when is_binary(name) and name != "" -> name
      _unset -> nil
    end
  end

  @doc """
  The tools whose `allow` this node honours from a policy component. Empty by default.

  A malformed value is read as the empty list rather than as "everything": this is a bound on
  what an untrusted component may resolve, and a bound that falls open on a typo is not one.
  """
  @spec allowable_tools() :: [String.t()]
  def allowable_tools do
    case Application.get_env(:ouroboros, :policy_allowable_tools, []) do
      tools when is_list(tools) -> Enum.filter(tools, &(is_binary(&1) and &1 != ""))
      _invalid -> []
    end
  end

  @doc false
  @spec max_rule_chars() :: pos_integer()
  def max_rule_chars, do: @max_rule_chars

  @doc false
  @spec max_request_bytes() :: pos_integer()
  def max_request_bytes, do: @max_request_bytes

  @doc false
  @spec max_verdict_bytes() :: pos_integer()
  def max_verdict_bytes, do: @max_verdict_bytes

  ## ── the component path ────────────────────────────────────────────────────────────────

  defp consult(request, asked) do
    opts = engine_opts()

    with {:ok, name} <- policy_name(),
         {:ok, entry} <- live_policy(name, opts),
         # W8. The block comes back with the verdict on provenance rather than being fetched
         # again, so what decides whether this node will `Component::deserialize` machine code
         # is a manifest it has *just* verified against its own trust policy (D24). Reading it
         # anywhere else would be reading it from something less than that.
         {:ok, precompiled} <- provenance(name, entry, opts),
         normalized = Request.new(request),
         {:ok, document} <- document(normalized),
         {:ok, verdict, rule} <- ask_component(name, entry, document, precompiled, opts) do
      settle(verdict, rule, name, entry, normalized, asked)
    else
      _no_policy_or_no_answer -> asked
    end
  end

  @doc """
  How long one decision may take, end to end. `config :ouroboros, :policy_decision_timeout_ms`.

  A malformed or out-of-range value falls back to the default rather than widening: this is a
  bound on a synchronous round trip that sits in front of every tool call the rules did not
  decide, and a bound a typo can remove is not one.
  """
  @spec decision_timeout() :: pos_integer()
  def decision_timeout do
    case Application.get_env(
           :ouroboros,
           :policy_decision_timeout_ms,
           @default_decision_timeout_ms
         ) do
      ms when is_integer(ms) and ms > 0 and ms <= @max_decision_timeout_ms -> ms
      _invalid -> @default_decision_timeout_ms
    end
  end

  # The node's own register, store and pool unless a test named others. See the moduledoc.
  defp engine_opts do
    case Application.get_env(:ouroboros, :wasm_policy_opts, []) do
      opts when is_list(opts) -> Keyword.take(opts, [:registry, :store_root, :pool])
      _invalid -> []
    end
  end

  defp policy_name do
    case configured_policy() do
      nil -> :inert
      name -> {:ok, name}
    end
  end

  # The `:live` lane-W entry of kind `:policy` with this name, on this node.
  #
  # `Rollout.live/1` filters on the *register's* kind, which is an index rather than a proof:
  # `provenance/3` is what holds the row to a manifest this node can verify, and it runs before
  # anything is loaded. A name that is not live, or is live as a capability, is a
  # misconfiguration and is said out loud once — a node that silently ran with no policy because
  # of a typo is a node whose operator believes it has one.
  defp live_policy(name, opts) do
    live = Rollout.live(Keyword.take(opts, [:registry]) ++ [kind: :policy])

    case Enum.find(live, &(Map.get(&1, :module) == "wasm/" <> name)) do
      %{component_sha256: sha} = entry when is_binary(sha) ->
        {:ok, entry}

      _absent ->
        warn_once(
          name,
          "config :ouroboros, :wasm_policy names #{inspect(name)}, which is not a live lane-W " <>
            "rollout of kind :policy on this node; the policy engine is inert and every " <>
            "request the rules do not decide is asked"
        )

        :no_policy
    end
  end

  # What the register row says has to be what somebody signed, and the two are separate files.
  #
  # The row supplies the sha this engine loads and instantiates. Its `kind` is written at deploy
  # from a manifest the rollout verified — but a checkpoint is a file on disk, and anything that
  # can write one can write a row whose `artifact_id` names a genuine policy manifest and whose
  # `component_sha256` names other bytes in the store. Without this check those bytes became the
  # node's permission engine, labelled with the planted sha.
  #
  # So before anything is loaded: the manifest the row names is verified against **this node's**
  # trust policy, its sha must be the row's sha, and its kind must be `:policy`. That is
  # `Ouroboros.Wasm.Boot`'s discipline for the same reason — a reboot restarting a wrapper from
  # a checkpoint is the same act as an engine consulting one.
  #
  # It runs once per decision and reads one small file; a failure makes the engine inert for
  # that name, said once, because a policy nobody can verify is not a policy this node has.
  defp provenance(name, entry, opts) do
    with {:ok, manifest} <- signed_manifest(entry, opts),
         :ok <- Verifier.verify_manifest(manifest, trust_policy(opts)),
         :ok <- matches_entry(manifest, entry) do
      {:ok, manifest.precompiled}
    else
      reason ->
        warn_once(
          {name, :provenance},
          "config :ouroboros, :wasm_policy names #{inspect(name)}, whose register entry does " <>
            "not match a manifest this node can verify (#{inspect(bounded_reason(reason))}); " <>
            "the policy engine is inert and every request the rules do not decide is asked"
        )

        :no_policy
    end
  end

  defp signed_manifest(entry, opts) do
    root = Keyword.get(opts, :store_root)

    store_opts =
      if is_binary(root) and root != "" and Wasm.allow_store_root_override?(),
        do: [root: root],
        else: []

    case Store.fetch_manifest(Map.get(entry, :artifact_id), store_opts) do
      {:ok, %Artifact{} = manifest} -> {:ok, manifest}
      {:error, reason} -> {:error, {:manifest_unusable, reason}}
    end
  rescue
    # `fetch_manifest/2` is total, but this sits in front of every permission decision and an
    # exception here would be one the caller's `rescue` reports as an authority failure rather
    # than as the inert engine it is.
    error -> {:error, {:manifest_unusable, Exception.message(error)}}
  end

  # The manifest describes the bytes the row names, and it describes a policy. Both halves:
  # a verified manifest for *some other* component is not provenance for this row, and a
  # verified capability manifest is not a policy however the row is labelled.
  defp matches_entry(%Artifact{} = manifest, entry) do
    cond do
      manifest.component_sha256 != Map.get(entry, :component_sha256) ->
        {:error, {:component_mismatch, :sha256}}

      kind_of(manifest) != :policy ->
        {:error, {:component_mismatch, :kind}}

      true ->
        :ok
    end
  end

  # This node's own trust policy, and **only** this node's — `Ouroboros.Wasm.Rollout`'s rule
  # verbatim, and unlike the register and the store it is not one of `:wasm_policy_opts`' test
  # seams. A node that could be told which signers to trust for its permission engine would be
  # verifying the sender rather than the artifact, and there is no test worth that.
  defp trust_policy(_opts), do: Application.get_env(:ouroboros, :upgrade_trust_policy, [])

  # One request, one verdict, **bounded**.
  #
  # This is a synchronous round trip through the node's one shared helper pool, sitting in front
  # of every tool call the rules did not decide, so it is the engine's job to bound it rather
  # than the pool's: a wedged helper otherwise cost one decision the instance deadline plus the
  # transport margin, twice over for the retry, while every other pool user queued behind it.
  # The decision has one deadline, the work runs in a process this one can kill, and a re-try is
  # spent only on the refusal that means "the instance I remember is gone".
  defp ask_component(name, entry, document, precompiled, opts) do
    sha = entry.component_sha256
    pool = Keyword.get(opts, :pool, Pool)
    instance = @instance_prefix <> sha
    deadline = System.monotonic_time(:millisecond) + decision_timeout()

    case bounded(deadline, fn -> Pool.call(instance, "evaluate", document, pool) end) do
      {:ok, {:ok, %{"payload" => payload}}} when is_binary(payload) ->
        verdict_or_ask(payload)

      # The one refusal a second attempt can fix, and the commonest one by far: nothing is
      # standing under this name — the first decision of the process's life, a helper that was
      # restarted, a component the cache evicted. Every other refusal has already spent the
      # round trip and a retry would only spend another.
      {:ok, {:error, %{refusal: "unknown_instance"}}} ->
        with :ok <- stand_up(sha, instance, precompiled, opts, deadline),
             {:ok, {:ok, %{"payload" => payload}}} when is_binary(payload) <-
               bounded(deadline, fn -> Pool.call(instance, "evaluate", document, pool) end) do
          verdict_or_ask(payload)
        else
          _still_no -> :no_answer
        end

      :expired ->
        expired(name, instance, pool)

      _refused ->
        :no_answer
    end
  end

  # The decision's deadline arrived. The answer is `ask`; the instance is dropped so the next
  # request stands a fresh one up rather than queueing behind whatever this one is still doing.
  #
  # The drop is issued from a process of its own and not waited on, deliberately: it goes to the
  # same pool that has just failed to answer in time, and making the *decision* wait for it
  # would be spending the bound this function exists to hold. The pool bounds it in turn — every
  # request it accepts carries a deadline, and a helper that answers neither is marked broken.
  defp expired(name, instance, pool) do
    _ = spawn(fn -> Pool.drop(instance, pool) end)

    warn_once(
      {name, :timeout},
      "the policy component #{inspect(name)} did not answer within " <>
        "#{decision_timeout()}ms; this request is asked, its instance is dropped, and the " <>
        "next request stands a fresh one up"
    )

    :no_answer
  end

  # Runs `fun` in a process this one can kill, and answers `:expired` at `deadline`.
  #
  # `spawn_monitor` rather than `Task.async`: a `Task` is *linked*, and the work here is a
  # `GenServer.call` that exits on its own timeout — an exit this function must absorb rather
  # than propagate into whatever turn is asking for a permission decision.
  defp bounded(deadline, fun) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)
    owner = self()
    tag = make_ref()

    {pid, monitor} = spawn_monitor(fn -> send(owner, {tag, fun.()}) end)

    receive do
      {^tag, result} ->
        Process.demonitor(monitor, [:flush])
        {:ok, result}

      {:DOWN, ^monitor, :process, ^pid, _reason} ->
        :no_answer
    after
      remaining ->
        Process.exit(pid, :kill)
        Process.demonitor(monitor, [:flush])
        :expired
    end
  end

  # Load and instantiate, as the policy world. The kind travels to the helper so a component
  # that is not in that world is refused at `load` — the manifest said `policy`, and this is
  # where that claim is checked against the bytes rather than believed.
  defp stand_up(sha, instance, precompiled, opts, deadline) do
    pool = Keyword.get(opts, :pool, Pool)

    with {:ok, {:ok, _loaded}} <-
           bounded(deadline, fn ->
             Pool.load_component(sha, precompiled, pool,
               kind: :policy,
               store: store_opts(Keyword.get(opts, :store_root))
             )
           end),
         {:ok, {:ok, _stood}} <-
           bounded(deadline, fn ->
             Pool.instantiate(instance, sha, "{}", Wasm.capability_limits(), pool, kind: :policy)
           end) do
      :ok
    else
      # Another process won the race and stood the same instance up. That is the instance this
      # request wants, so it is not a failure.
      {:ok, {:error, %{refusal: "instance_exists"}}} -> :ok
      _refused_or_expired -> :error
    end
  end

  ## ── the verdict ───────────────────────────────────────────────────────────────────────

  @doc """
  One strict reading of a component's verdict: `{:ok, decision, rule}` or `:unreadable`.

  Public because it is a **contract between two implementations**, not an internal detail.
  `ouro`'s `wasm_cli::PolicyVerdict::parse` reads the same documents so an author can see what
  the node will make of a verdict before deploying one, and the two are pinned to
  `test/support/wasm_golden/policy_verdicts.json` by a test on each side — the discipline W10
  used for the hook narrowing (D14).

  ## Why it is this strict

  A verdict is an object with **exactly** the keys `decision` and `rule`, no key repeated,
  `decision` exactly one of the three lower-case words, `rule` a string, and the whole document
  at most #{@max_verdict_bytes} bytes.

  The repeated key is the reason the grammar is written down rather than left to a decoder.
  Elixir's JSON decoder keeps the **first** occurrence of a duplicated key and `serde_json`
  keeps the **last**, so `{"decision":"ask","decision":"deny"}` was `ask` here and `deny` in
  `ouro wasm policy` — a component could show an operator one word and hand this node another,
  and in the other order it turned a reviewed `ask` into an honoured `allow`. So the document is
  decoded into an ordered list of pairs and the key list is checked as a whole, rather than
  through a map that has already thrown the evidence away.

  Everything the grammar rejects is `:unreadable`, which the engine answers as `ask`.
  """
  @spec read_verdict(term()) :: {:ok, verdict(), String.t()} | :unreadable
  def read_verdict(payload) when is_binary(payload) do
    if byte_size(payload) > @max_verdict_bytes do
      :unreadable
    else
      with {:ok, pairs} <- decode_pairs(payload) do
        verdict_of(pairs)
      end
    end
  end

  def read_verdict(_payload), do: :unreadable

  # `:json.decode/3` with the object accumulator left as the list it builds, rather than the map
  # the default `object_finish` folds it into: a map cannot say that a key arrived twice. The
  # third element of the return is what is left over, so trailing data — a second document, a
  # byte-order mark's remains — is a refusal rather than a parse of the first half.
  defp decode_pairs(payload) do
    # Tagged, because an object and an array both come back as lists once `object_finish` stops
    # folding: `[1,2,3]` is not a verdict with three keys, and `elem/2` on its elements raises.
    decoders = %{object_finish: fn acc, old -> {{:object, :lists.reverse(acc)}, old} end}

    case :json.decode(payload, :ok, decoders) do
      {{:object, pairs}, :ok, <<>>} -> {:ok, pairs}
      _not_one_object -> :unreadable
    end
  rescue
    _error -> :unreadable
  catch
    _kind, _reason -> :unreadable
  end

  defp verdict_of(pairs) do
    keys = Enum.map(pairs, &elem(&1, 0))

    with true <- Enum.all?(keys, &is_binary/1),
         # Exactly these two, each once. A repeated key sorts to `["decision", "decision"]`,
         # which is not this list, so the closed-key check is also the duplicate check.
         true <- Enum.sort(keys) == @verdict_keys,
         {"decision", spelling} <- List.keyfind(pairs, "decision", 0),
         {"rule", rule} <- List.keyfind(pairs, "rule", 0),
         true <- is_binary(rule),
         decision when not is_nil(decision) <- Map.get(@decisions, spelling) do
      {:ok, decision, rule(rule)}
    else
      _outside_the_grammar -> :unreadable
    end
  end

  # A component's own sentence, made safe to put beside the node's: no control character, no
  # format character, no line or paragraph separator, and at most #{@max_rule_chars} of what is
  # left. The same class `Ouroboros.Wasm.Capability.Describe` refuses in a description, flattened
  # here rather than refused, because a rule this node cannot render is not a reason to turn a
  # `deny` into an `ask`.
  # `rule` is a required string in the grammar above, so this is only ever handed one.
  defp rule(text) when is_binary(text) do
    cleaned =
      text
      |> String.replace(~r/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u, " ")
      |> String.slice(0, @max_rule_chars)
      |> String.trim()

    if cleaned == "" or not String.valid?(cleaned),
      do: "the component stated no rule",
      else: cleaned
  end

  # A verdict outside the grammar is not a refusal to retry: the component answered, and what it
  # answered is unreadable, which this lane spells `ask`.
  defp verdict_or_ask(payload) do
    case read_verdict(payload) do
      {:ok, decision, rule} -> {:ok, decision, rule}
      :unreadable -> {:ok, :ask, "the component's verdict could not be read"}
    end
  end

  ## ── settling ──────────────────────────────────────────────────────────────────────────

  defp settle(:deny, rule, name, entry, request, _asked),
    do: decided(:deny, :deny, rule, name, entry, request)

  defp settle(:allow, rule, name, entry, request, asked) do
    if request.tool in allowable_tools() do
      decided(:allow, :approve, rule, name, entry, request)
    else
      # The default, and the one the moduledoc calls the whole posture: an `allow` for a tool no
      # operator listed is read as the question it was already going to be.
      asked
    end
  end

  defp settle(:ask, _rule, _name, _entry, _request, asked), do: asked

  # An honoured verdict: recorded as this engine's own decision, then returned with the
  # component's rule as the reason a person or a model reads.
  defp decided(outcome, ledger_decision, rule, name, entry, request) do
    stated = "Policy(#{name}@#{short(entry.component_sha256)}): #{@untrusted} #{rule}"

    written =
      Permissions.record(decision_id(entry, request), %{
        decision: ledger_decision,
        scope: :once,
        # The slot `Control.Permissions`' answer type reserved and nothing occupied until now.
        actor: :classifier,
        # The map is what the ledger reads: `id` becomes the entry's `rule_id` and carries the
        # component's sha, `reason` carries the rule string. Both, because "which bytes decided"
        # and "what they said" are different questions and an audit needs each.
        rule_ref: %{
          scope: :policy,
          id: @instance_prefix <> entry.component_sha256,
          pattern: rule
        },
        reason: rule,
        request: request
      })

    recorded(outcome, stated, written)
  end

  # `Control.Permissions`' rule, applied to a component's verdict for the same reasons.
  #
  # An **allow** nobody can account for has not been granted: it is downgraded to `ask`, which
  # is a human question rather than a silent authorisation. A **deny** stands, because refusing
  # without an audit entry is still refusing — and turning it into an ask would be the one thing
  # this lane never does, which is widen. Before this the result was discarded, so a component's
  # allow stood with a dead ledger while an operator's own rule was already becoming
  # `{:ask, :unrecordable}` two functions away.
  defp recorded(outcome, stated, :ok = _written), do: {outcome, stated}
  defp recorded(:deny, stated, _failed), do: {:deny, stated}

  defp recorded(:allow, _stated, {:error, reason}) do
    Logger.warning(
      "wasm policy allow not recorded, downgrading to ask: #{inspect(bounded_reason(reason))}"
    )

    {:ask, :unrecordable}
  end

  # Stable per request and per component, so a retry after a lost answer records the same entry
  # rather than a second one — `Control.Permissions.evaluation_id/2`'s discipline.
  defp decision_id(entry, %Request{} = request) do
    digest =
      [
        entry.component_sha256,
        request.principal.session_id || "",
        request.tool,
        request.command || "",
        Enum.join(request.paths, ":"),
        to_string(request.mode)
      ]
      |> Enum.join("\n")

    "perm-policy-" <>
      (:crypto.hash(:sha256, digest) |> Base.encode16(case: :lower) |> binary_part(0, 32))
  end

  defp short(sha) when is_binary(sha) and byte_size(sha) >= 12, do: binary_part(sha, 0, 12)
  defp short(sha), do: to_string(sha)

  ## ── the request document ──────────────────────────────────────────────────────────────

  @doc """
  The JSON a policy component is handed for `request`, or `:too_large`.

  Public because it is the contract: `tui/wasm/guest/src/policy.rs` documents this shape for an
  author, `ouro wasm policy` sends one an operator typed, and a test that built its own would be
  testing a document the node never sends.
  """
  @spec document(Request.t()) :: {:ok, String.t()} | :too_large
  def document(%Request{} = request) do
    {kept, dropped} = context(request.context)

    body =
      %{
        "tool" => request.tool,
        "mode" => to_string(request.mode),
        "input" => %{
          "command" => request.command,
          "paths" => request.paths,
          "write_paths" => request.write_paths,
          "domains" => request.domains
        },
        "principal" => %{
          "session_id" => request.principal.session_id,
          "provider" => scalar(request.principal.provider),
          "node" => to_string(request.principal.node)
        },
        "workspace" => request.root,
        "context" => kept,
        "context_dropped" => dropped
      }
      |> redact()

    encoded = JSON.encode!(body)

    if byte_size(encoded) > @max_request_bytes, do: :too_large, else: {:ok, encoded}
  rescue
    _error -> :too_large
  end

  # Scalars only, and the names of what was left out.
  #
  # A context value that is a map or a list is dropped rather than serialised: the context is
  # free-form by contract, so it is the one part of a request whose shape this module cannot
  # bound in advance. Naming the dropped keys is what keeps that from being a silent partial
  # view — a policy that cares can see that something was withheld and answer `ask`.
  defp context(context) when is_map(context) do
    {kept, dropped} =
      context
      |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
      |> Enum.take(@max_context_keys)
      |> Enum.reduce({%{}, []}, fn {key, value}, {kept, dropped} ->
        name = to_string(key)

        case scalar(value) do
          :drop -> {kept, [name | dropped]}
          scalar -> {Map.put(kept, name, scalar), dropped}
        end
      end)

    {kept, Enum.reverse(dropped)}
  end

  defp context(_absent), do: {%{}, []}

  defp scalar(nil), do: nil
  defp scalar(value) when is_binary(value) or is_number(value) or is_boolean(value), do: value
  defp scalar(value) when is_atom(value), do: Atom.to_string(value)
  defp scalar(_other), do: :drop

  ## ── redaction ─────────────────────────────────────────────────────────────────────────

  @doc """
  What is taken out of a request document before a component sees it.

  Three passes, and it is worth being exact about each because the first version of this
  sentence claimed more than the code did:

    1. **Credential-shaped keys.** A map key matching `#{inspect(@credential_key)}` — after
       every run of non-alphanumerics is folded to `_`, so `X-Api-Key` and `apiKey` both
       match — has its whole value replaced. This is `Jido.Harness.Redaction`'s rule.
    2. **Well-known token shapes, in every string.** `Bearer <run>`, AWS access key ids,
       `sk-…`, GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`, Slack `xox…`, PEM
       private-key blocks, and `NAME=value` or `NAME: value` where NAME is credential-shaped.
    3. **This node's own secrets.** Every environment value under a credential-shaped name,
       longest first, wherever it appears.

  **It is a heuristic and the second pass is the heuristic part.** A credential that does not
  look like any of these — an opaque database URL's password, a bearer token spelled without
  the word, a company's own key format — reaches the component. And it must: the whole reason a
  policy sees the command line is that a policy that may deny `curl` needs to read the `curl`,
  and that is the same sentence D8 makes about what a hook may see. What this pass buys is that
  the *obvious* spellings do not travel; what bounds the rest is that a component's whole reach
  is a log line the helper truncates.
  """
  @spec redact(term()) :: term()
  def redact(value), do: scrub(value, environment_secrets())

  defp scrub(map, secrets) when is_map(map) and not is_struct(map) do
    Map.new(map, fn {key, inner} ->
      if credential_key?(key),
        do: {key, @redacted},
        else: {key, scrub(inner, secrets)}
    end)
  end

  defp scrub(list, secrets) when is_list(list), do: Enum.map(list, &scrub(&1, secrets))

  defp scrub(text, secrets) when is_binary(text) do
    text
    |> then(
      &Enum.reduce(@token_shapes, &1, fn {pattern, into}, acc ->
        Regex.replace(pattern, acc, into)
      end)
    )
    |> then(
      &Enum.reduce(secrets, &1, fn secret, acc -> String.replace(acc, secret, @redacted) end)
    )
  end

  defp scrub(scalar, _secrets), do: scalar

  defp credential_key?(key) do
    key
    |> to_string()
    |> String.replace(~r/[^a-zA-Z0-9]+/, "_")
    |> String.match?(@credential_key)
  end

  # The node's own environment, asked of the harness's own reader so there is one list of what
  # counts as a secret name. Computed once per process rather than per string: this runs on the
  # permission path.
  defp environment_secrets do
    case Process.get(@secrets_key) do
      nil ->
        secrets = Redaction.secrets_from_env(System.get_env())
        Process.put(@secrets_key, secrets)
        secrets

      secrets ->
        secrets
    end
  end

  ## ── the signed eval spec (the rollout's gate for a policy component) ──────────────────

  @doc """
  Validates a policy component's signed evaluation spec.

  A policy is not a mesh agent, so `Ouroboros.Upgrade.Rollout.Evaluation`'s probe grammar — a
  message, an expectation over agent state — says nothing about one. What a policy's spec
  declares instead is a list of **cases**: a permission request, and the decision this component
  must reach about it.

      %{
        cases: [
          %{request: %{"tool" => "bash", "input" => %{"command" => "curl x"}},
            expect: %{decision: :deny}},
          %{request: %{"tool" => "bash", "input" => %{"command" => "ls"}},
            expect: %{decision: :ask}}
        ],
        budget_ms: 5_000
      }

  D12 applies here exactly as it does to a capability: there is no build peer behind lane W, so
  the signed spec *is* the test story, and the signer requires one.
  """
  @spec validate_eval(term()) :: {:ok, map()} | {:error, term()}
  def validate_eval(spec) when is_map(spec) and not is_struct(spec) do
    with :ok <- known_keys(spec, [:cases, :budget_ms]),
         {:ok, cases} <- validate_cases(Map.get(spec, :cases)),
         :ok <- certifies_a_refusal(cases),
         {:ok, budget} <- validate_budget(Map.get(spec, :budget_ms, @default_case_budget_ms)),
         normalized = %{cases: cases, budget_ms: budget},
         :ok <- bounded_spec(normalized) do
      {:ok, normalized}
    end
  end

  def validate_eval(other), do: {:error, {:invalid_eval_spec, {:not_a_map, describe(other)}}}

  # At least one case must expect a `deny` or an `ask`.
  #
  # A spec whose every expectation is `allow` certifies nothing this lane cares about. An
  # `allow` is the one verdict the node does not honour by default, so a component could satisfy
  # such a spec on every target and still be the only thing it must never be — something that
  # denies what it should not, or asks about everything. What the signed spec *is* here is the
  # test story (D12), and a test story with no refusal in it is a claim that the component said
  # yes twice.
  defp certifies_a_refusal(cases) do
    if Enum.any?(cases, &(&1.expect.decision in [:deny, :ask])),
      do: :ok,
      else: {:error, {:invalid_eval_spec, :no_case_expects_a_refusal}}
  end

  defp known_keys(spec, allowed) do
    case Map.keys(spec) -- allowed do
      [] -> :ok
      unknown -> {:error, {:invalid_eval_spec, {:unknown_spec_keys, Enum.sort(unknown)}}}
    end
  end

  defp validate_cases(cases) when is_list(cases) and cases != [] do
    cond do
      length(cases) > @max_cases ->
        {:error, {:invalid_eval_spec, {:too_many_cases, length(cases), @max_cases}}}

      true ->
        cases
        |> Enum.with_index()
        |> Enum.reduce_while({:ok, []}, fn {one, index}, {:ok, acc} ->
          case validate_case(one, index) do
            {:ok, valid} -> {:cont, {:ok, [valid | acc]}}
            {:error, _reason} = error -> {:halt, error}
          end
        end)
        |> case do
          {:ok, valid} -> {:ok, Enum.reverse(valid)}
          error -> error
        end
    end
  end

  defp validate_cases(_absent), do: {:error, {:invalid_eval_spec, :cases_required}}

  defp validate_case(one, index) when is_map(one) and not is_struct(one) do
    request = Map.get(one, :request)
    decision = one |> Map.get(:expect, %{}) |> expected_decision()

    cond do
      Map.keys(one) -- [:request, :expect] != [] ->
        {:error, {:invalid_eval_spec, {:unknown_case_keys, index}}}

      not (is_map(request) and not is_struct(request)) ->
        {:error, {:invalid_eval_spec, {:case_request_not_a_map, index}}}

      is_nil(decision) ->
        {:error, {:invalid_eval_spec, {:unknown_expected_decision, index}}}

      true ->
        {:ok, %{request: request, expect: %{decision: decision}}}
    end
  end

  defp validate_case(_other, index),
    do: {:error, {:invalid_eval_spec, {:case_not_a_map, index}}}

  defp expected_decision(expect) when is_map(expect) do
    case Map.get(expect, :decision) do
      decision when decision in [:allow, :deny, :ask] -> decision
      decision when is_binary(decision) -> Map.get(@decisions, decision)
      _other -> nil
    end
  end

  defp expected_decision(_other), do: nil

  defp validate_budget(budget) when is_integer(budget) and budget > 0 do
    if budget > @max_case_budget_ms,
      do: {:error, {:invalid_eval_spec, {:invalid_budget_ms, budget}}},
      else: {:ok, budget}
  end

  defp validate_budget(other),
    do: {:error, {:invalid_eval_spec, {:invalid_budget_ms, describe(other)}}}

  # A spec is signed, replicated to every target and stored durably, so it is bounded and it is
  # bounded on what it *costs* rather than on how it was written: the encoded form is the thing
  # that travels.
  defp bounded_spec(spec) do
    size = spec |> :erlang.term_to_binary() |> byte_size()

    if size > @max_spec_bytes,
      do: {:error, {:invalid_eval_spec, {:eval_spec_too_large, size, @max_spec_bytes}}},
      else: :ok
  end

  ## ── the rollout's two gates for a policy component ────────────────────────────────────

  @doc """
  The rollout's probe gate for a policy component: does it stand up and answer a verdict?

  A policy is not a mesh agent, so `Ouroboros.Upgrade.Rollout.Probe`'s "start it, message it,
  stop it" says nothing about one. This is the same question asked in the shape this world has:
  load as a policy, instantiate under the deploy's own bounds, hand it one well-formed request,
  and require a *readable* verdict back. Any of the three decisions passes — what is being
  probed is liveness, not opinion.

  `state` is `Ouroboros.Wasm.Rollout.start_state/2`'s map. Never raises; the rollout treats an
  exception as ambiguity and ambiguity quarantines a cluster.
  """
  @spec probe(map(), keyword()) :: :ok | {:error, term()}
  def probe(state, opts \\ []) when is_map(state) and is_list(opts) do
    throwaway(state, opts, fn instance, pool ->
      case evaluate_once(instance, pool, probe_request()) do
        {:ok, _decision, _rule} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end)
  end

  @doc """
  The rollout's evaluation gate for a policy component: run the signed cases.

  Answers the same summarized shape `Ouroboros.Upgrade.Rollout.Evaluation.summarize/1` produces,
  so `Ouroboros.Wasm.Rollout`'s settle logic reads a policy's report and a capability's report
  with one function.
  """
  @spec run_eval(map(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def run_eval(state, spec, opts \\ []) when is_map(state) and is_map(spec) and is_list(opts) do
    throwaway(state, opts, fn instance, pool ->
      started = System.monotonic_time(:millisecond)

      results =
        spec.cases
        |> Enum.with_index()
        |> Enum.map(fn {one, index} -> run_case(instance, pool, one, index) end)

      passed = Enum.count(results, &(&1.outcome == :passed))
      total_ms = System.monotonic_time(:millisecond) - started

      {:ok,
       %{
         node: node(),
         probes: length(results),
         passed: passed,
         failed: length(results) - passed,
         total_ms: total_ms,
         budget_ms: spec.budget_ms,
         within_budget?: total_ms <= spec.budget_ms,
         satisfied?: passed == length(results) and total_ms <= spec.budget_ms,
         failures:
           results
           |> Enum.filter(&(&1.outcome == :failed))
           |> Enum.take(5)
           |> Enum.map(&Map.take(&1, [:index, :reason]))
       }}
    end)
  end

  defp run_case(instance, pool, one, index) do
    expected = one.expect.decision

    case encode(one.request) do
      :error ->
        %{index: index, outcome: :failed, reason: :case_request_not_encodable}

      {:ok, encoded} ->
        case evaluate_once(instance, pool, encoded) do
          {:ok, ^expected, _rule} ->
            %{index: index, outcome: :passed, reason: nil}

          {:ok, decision, _rule} ->
            %{index: index, outcome: :failed, reason: {:expected, expected, decision}}

          {:error, reason} ->
            %{index: index, outcome: :failed, reason: bounded_reason(reason)}
        end
    end
  end

  defp encode(term) do
    {:ok, JSON.encode!(term)}
  rescue
    _error -> :error
  end

  # One instance, one component, dropped on every path including an exception — the discipline
  # `Ouroboros.Wasm.Capability.capture_describe/2` states, for the same reason: this runs under
  # `:erpc` from a coordinating node, and an instance nobody drops is one the helper holds until
  # its table is full.
  defp throwaway(state, opts, body) do
    pool = Map.get(state, :pool, Pool)
    sha = Map.get(state, :component)
    instance = @instance_prefix <> "gate/" <> unique()

    try do
      with {:ok, sha} <- component_sha(sha),
           # W8. The deploy gates take the same form the live engine will: the state carries the
           # verified manifest's block (`Ouroboros.Wasm.Rollout.start_state/2`), so a probe or an
           # evaluation exercises the artifact this node would actually load rather than a form
           # nothing will run — and falls back the same way if the helper refuses it.
           {:ok, _loaded} <- load_component(state, sha, pool),
           {:ok, _stood} <-
             Pool.instantiate(instance, sha, config(state), limits(state), pool,
               kind: :policy,
               owner: Keyword.get(opts, :owner)
             ) do
        body.(instance, pool)
      else
        {:error, reason} -> {:error, bounded_reason(reason)}
        other -> {:error, bounded_reason(other)}
      end
    rescue
      error -> {:error, {:policy_gate_exception, Exception.message(error)}}
    catch
      kind, reason -> {:error, {:policy_gate_exception, "#{kind}: #{bounded_reason(reason)}"}}
    after
      _ = Pool.drop(instance, pool)
    end
  end

  defp evaluate_once(instance, pool, document) do
    case Pool.call(instance, "evaluate", document, pool) do
      {:ok, %{"payload" => payload}} when is_binary(payload) ->
        verdict_or_ask(payload)

      {:ok, other} ->
        {:error, {:malformed_evaluate_result, other |> Map.keys() |> Enum.take(8)}}

      {:error, reason} ->
        {:error, bounded_reason(reason)}
    end
  end

  # A request with every key the document contract names, so a probe exercises the same shape a
  # real call does rather than an empty object a lenient component would answer anyway.
  defp probe_request do
    JSON.encode!(%{
      "tool" => "wasm.policy.probe",
      "mode" => "read",
      "input" => %{"command" => nil, "paths" => [], "write_paths" => [], "domains" => []},
      "principal" => %{"session_id" => nil, "provider" => "rollout", "node" => to_string(node())},
      "workspace" => nil,
      "context" => %{},
      "context_dropped" => []
    })
  end

  defp component_sha(sha) when is_binary(sha) and sha != "", do: {:ok, sha}
  defp component_sha(other), do: {:error, {:invalid_component, describe(other)}}

  defp load_component(state, sha, pool) do
    precompiled =
      case Map.get(state, :precompiled) do
        block when is_map(block) -> if Artifact.precompiled?(block), do: block
        _absent -> nil
      end

    Pool.load_component(sha, precompiled, pool,
      kind: :policy,
      store: store_opts(Map.get(state, :store_root))
    )
  end

  # The node's own store root unless a caller named one *and* this build honours the override,
  # which is this repository's test environment and nowhere else — `Ouroboros.Wasm.Capability`'s
  # rule, verbatim, because a directory name that decides which unsigned bytes get instantiated
  # is not a setting.
  defp store_opts(root) do
    if is_binary(root) and root != "" and Wasm.allow_store_root_override?(),
      do: [root: root],
      else: []
  end

  defp config(state) do
    case Map.get(state, :config) do
      config when is_binary(config) -> config
      _absent -> "{}"
    end
  end

  defp limits(state) do
    case Map.get(state, :limits) do
      limits when is_map(limits) -> limits
      _absent -> Wasm.capability_limits()
    end
  end

  defp unique, do: Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

  ## ── odds and ends ─────────────────────────────────────────────────────────────────────

  # Once per name, for the life of the node. A misconfigured policy is a fact about the node's
  # configuration and not about the call that discovered it, so it is said when it is discovered
  # and not on every request after.
  defp warn_once(name, message) do
    key = {__MODULE__, :warned, name}

    if :persistent_term.get(key, false) == false do
      :persistent_term.put(key, true)
      Logger.warning(message)
    end

    :ok
  end

  @doc false
  @spec forget_warning(String.t()) :: :ok
  def forget_warning(name) do
    _ = :persistent_term.erase({__MODULE__, :warned, name})
    :ok
  end

  defp bounded_reason(reason) when is_map(reason), do: Map.take(reason, [:refusal, :code])
  defp bounded_reason(reason) when is_atom(reason) or is_binary(reason), do: reason
  defp bounded_reason(reason), do: describe(reason)

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)

  @doc """
  The kind a manifest or a register entry declares, defaulting to `:capability`.

  One reading for both, because both are documents this build may have written before there were
  two kinds: a manifest decoded out of the store with no `:kind` key, and a checkpoint entry
  whose struct default is `nil`. Neither is a policy — a policy is something a manifest says
  positively — so anything that is not `:policy` is a capability, which is where every such
  record has always been read.
  """
  @spec kind_of(Artifact.t() | map()) :: :capability | :policy
  def kind_of(%{kind: :policy}), do: :policy
  def kind_of(_capability_or_unstated), do: :capability
end
