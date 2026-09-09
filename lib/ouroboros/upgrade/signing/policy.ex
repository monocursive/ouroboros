defmodule Ouroboros.Upgrade.Signing.Policy do
  @moduledoc """
  The gate a signer node applies to a full manifest *before* any signature exists.

  This is the independence the rest of the upgrade lane cannot supply for itself. The
  forge decides what to build; `Ouroboros.Wasm.Verifier` decides what a target node will
  load. Both of those run inside the application an agent can reach. This policy runs in
  the process that holds the key, on a host whose supervision tree contains nothing else,
  and it is the only check in the system that happens while refusing is still free —
  after a signature exists, every later check is arguing with cryptography.

  ## What a policy is given, and what it trusts

  `evaluate/2` receives the **whole submitted manifest** and the component bytes it
  describes, not the canonical payload the requester wants signed. That is the entire
  point: a payload is a hash of a manifest, and a manifest is a set of claims. The
  shipped policy recomputes every claim that can be recomputed — the digest and the size,
  from the bytes actually in hand — so a requester that precomputed a flattering manifest
  is refused on arithmetic rather than trusted.

  It trusts exactly one thing about the requester: nothing.

  ## The world rule is structural

  A component's `world` must be the one its `kind` requires, and there is no
  configuration that widens that. A world is a linker contract; a signer that could be
  argued into certifying one this build does not implement would have certified a
  contract nobody on any loading node can honour.

  ## What a signer cannot know

  Some checks belong to the target and are named here so nobody mistakes their absence
  for an oversight:

    * **Epoch ordering.** A signer sees a number. It has no view of any cluster's epoch
      watermark, and asking it to would make it a participant in the deployment it is
      supposed to be independent of. Positivity is checked, and distance from what this
      node can see (`@max_epoch_distance`); monotonicity is the target register's job and
      survives this signature entirely.
    * **What the linker will accept.** The declared imports are provenance and review
      surface (D5). The boundary is the helper's linker on the loading node, which
      defines exactly the world's imports and fails instantiation on anything else.

  ## Refusals are values

  Every failure is `{:refused, reason}` with a named reason. Nothing raises across this
  boundary: an exception here would reach the requester through `:erpc` as transport
  ambiguity, and a signing service must never let "I refuse" and "I do not know what
  happened" look alike.

  ## Configuration

    * `config :ouroboros, :signing_policy` — the module implementing this behaviour,
      defaulting to `Ouroboros.Upgrade.Signing.Policy.Default`.
    * `config :ouroboros, :signing_require_wasm_eval` — when true, a manifest must carry
      a valid evaluation spec in `metadata.eval`, and it defaults to **true** (D12).
      There is no build peer that ran a test suite here, so the signed eval spec *is* the
      test story: it is what makes "this capability declared how it would be judged" a
      precondition of a signature rather than a hope.
  """

  @default_rate_limit_window_ms 60_000
  @default_max_requesters 64

  @typedoc "Everything the service knows about the request, and nothing about the key."
  @type context :: %{
          required(:signer_id) => String.t(),
          required(:requester) => node(),
          optional(:require_wasm_eval) => boolean(),
          optional(:component_bytes) => binary() | nil,
          optional(:max_artifact_bytes) => pos_integer(),
          optional(atom()) => term()
        }

  @doc """
  Decides whether this artifact may be signed at all.

  `{:ok, findings}` admits it, and the findings are journaled next to the decision as the
  evidence behind it. `{:refused, reason}` is final and typed.
  """
  @callback evaluate(artifact :: Ouroboros.Wasm.Artifact.t() | struct(), context :: context()) ::
              {:ok, findings :: map()} | {:refused, reason :: term()}

  @doc "Returns the configured policy module, defaulting to the shipped one."
  @spec configured() :: module()
  def configured do
    case Application.get_env(:ouroboros, :signing_policy, __MODULE__.Default) do
      module when is_atom(module) and not is_nil(module) -> module
      _invalid -> __MODULE__.Default
    end
  end

  @doc """
  Applies a sliding-window admission limit and returns the window to keep.

  Kept here, with the artifact rules, because it is a refusal like any other — but it is
  a function of the requester and the clock rather than of the bytes, so the window
  itself lives in the service's state and is threaded through.

  The window is bounded in both directions: entries older than `:window_ms` are dropped
  on every pass, and the number of distinct requesters tracked is capped, evicting the
  least recently seen. A caller that invents node names cannot grow this map.

  Honest limit: the requester is whatever the caller said it was. A hostile connected
  node can vary it, exactly as it can call the service at all. This bounds accidents,
  runaway retries, and honest clients — not an adversary who already has distribution
  authority.
  """
  @spec rate_limit(map(), node(), integer(), keyword()) ::
          {:ok, map()} | {:refused, {:rate_limited, node(), non_neg_integer(), pos_integer()}}
  def rate_limit(window, requester, now_ms, opts)
      when is_map(window) and is_atom(requester) and is_integer(now_ms) and is_list(opts) do
    max = Keyword.fetch!(opts, :max)
    window_ms = Keyword.get(opts, :window_ms, @default_rate_limit_window_ms)
    max_requesters = Keyword.get(opts, :max_requesters, @default_max_requesters)

    recent =
      window
      |> Map.get(requester, [])
      |> Enum.filter(&(now_ms - &1 < window_ms))

    if length(recent) >= max do
      {:refused, {:rate_limited, requester, length(recent), max}}
    else
      window
      |> Map.put(requester, [now_ms | recent])
      |> prune(now_ms, window_ms)
      |> evict(max_requesters)
      |> then(&{:ok, &1})
    end
  end

  defp prune(window, now_ms, window_ms) do
    window
    |> Enum.reduce(%{}, fn {requester, stamps}, acc ->
      case Enum.filter(stamps, &(now_ms - &1 < window_ms)) do
        [] -> acc
        kept -> Map.put(acc, requester, kept)
      end
    end)
  end

  defp evict(window, max_requesters) when map_size(window) <= max_requesters, do: window

  defp evict(window, max_requesters) do
    window
    |> Enum.sort_by(fn {_requester, stamps} -> -Enum.max(stamps) end)
    |> Enum.take(max_requesters)
    |> Map.new()
  end
end

defmodule Ouroboros.Upgrade.Signing.Policy.Default do
  @moduledoc """
  The shipped independent gate: recompute everything, and refuse outside the world.

  An `Ouroboros.Wasm.Artifact` is checked by seven families, in the order docs/WASM.md §7.5
  states them:

  1. **Shape and size.** Non-empty id and name, positive epoch, 64-hex lower-case
     `component_sha256`, positive `size` within `:signing_max_artifact_bytes`, a string
     world, a list of string imports, a plain map for metadata.
  2. **World, and the kind it follows from.** `kind` is `:capability` or `:policy`, and
     `world == Ouroboros.Wasm.world_for(kind)`. This is the hard rule, and it is hard: there
     is no configuration that widens it. A signer that can be argued
     into signing a component for a world this build does not implement is a signer that has
     certified a linker contract nobody here can honour — and one that signed a `:policy`
     manifest carrying the capability world would have certified a permission engine's
     component into a world the model can send messages to (W15, contract C7).
  3. **Recomputation.** The submitted component bytes arrive in `context.component_bytes`
     — the same posture as the advisory payload, supplied per request — and the sha256
     and the size are recomputed from them. Absent bytes are a refusal
     (`:missing_component_bytes`), never a pass: a manifest nobody checked against bytes
     is a set of claims, and this is the one process whose whole job is not to believe
     them.
  5. **The precompiled block** (W8, D22). `precompiled` is absent, or it is exactly
     `%{wasmtime, target, sha256, size}` — a 64-hex digest that is *not* the component's own,
     a positive size within the same multiple of the artifact ceiling `Ouroboros.Wasm.Bundle`
     admits, and two printable bounded strings that are what a helper's `doctor` would have
     printed. What this block authorizes is a loading node calling `Component::deserialize` on
     machine code it did not produce, which is `unsafe` for a reason (D24), so the digest that
     makes that sound has to be inside what the signature covers. What is deliberately *not*
     checked is whether this signer recognises the version or the triple: that is a fact about
     a loading node, and a node that does not match falls back to the source form by itself.
     Nothing here maps the artifact, for family 4's reason.
  4. **Imports.** The declared list must be a subset of the world's, which in v1 is
     `["log"]`. This is a *policy* check and is documented as one (D5): the security
     boundary is the helper's linker, which defines exactly the world's imports and fails
     instantiation on anything undeclared. Nothing here parses the component binary, and
     nothing here needs the `ouro-wasm` helper to be present on the signer node — a
     signer that cannot parse components is still not a hole, because the list it is
     reading is provenance and review surface rather than the enforcement mechanism.
  6. **Provenance.** `metadata.author` must be present. `metadata.eval` is validated by
     `Ouroboros.Upgrade.Rollout.Evaluation.validate/1` whenever it is there, and is
     **required by default** (D12, `:signing_require_wasm_eval`). `source_sha256`,
     `language`, and `test_report` are optional and are checked for shape when present:
     a guest toolchain that produces a test report is welcome to say so, and nothing here
     pretends one exists when it does not.
  A **policy** manifest differs in exactly two more places, and both follow from what a policy
  component is. Its `eval` spec is a list of `{request, expect: {decision}}` cases validated by
  `Ouroboros.Wasm.PolicyEngine.validate_eval/1` rather than a probe spec over agent state — a
  policy is not a mesh agent, so the capability grammar says nothing about one. And it may
  **not** declare a `start` block: `metadata.start` is the claim "this runs continuously under
  this durable mesh id", and a policy component has no wrapper agent, is reached only by the
  permission engine, and would be claiming a cluster-wide id nothing starts.

  7. **Start block.** `metadata.start`, when present, must be exactly
     `%{id: binary, config: binary}` and the id must be exactly `"wasm/" <> name` for the
     name in *this* manifest. It is the claim "this capability runs continuously under this
     id", which a signature should cover — and binding it to the prefix alone was not
     binding it at all: a component named `evil` could declare `wasm/greeter` and be signed,
     recorded in the register as `wasm/evil`, and then claim the cluster-wide id everybody
     trusts as `greeter`. The name's own charset (`Ouroboros.Wasm.Artifact.name?/1`) is what
     keeps that id from being a path or a bidirectional-override string.
  """

  @behaviour Ouroboros.Upgrade.Signing.Policy

  alias Ouroboros.Upgrade.Epoch
  alias Ouroboros.Upgrade.Rollout.Evaluation
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm

  @sha256_hex 64

  # v1's world imports exactly one function (docs/WASM.md §7.1). Growth of this set is a
  # signing-policy event, which is why the list is here and not in configuration.
  @world_imports ["log"]

  # The namespace a durable agent id lives in. `Ouroboros.Wasm.Rollout` writes the
  # registry entry's module as `"wasm/" <> name` for the same reason. The id's own bound is
  # the *name's* bound (`Ouroboros.Wasm.Artifact.name?/1`), because the id is exactly this
  # prefix and that name.
  @start_prefix "wasm/"
  @max_start_config_bytes 16_384

  # How far above what this node has actually seen an epoch may be.
  #
  # `Ouroboros.Upgrade.Rollout.Registry` refuses an epoch at or above its plausibility
  # ceiling, and admits one only when it is strictly greater than its watermark. Between
  # those two rules, a single entry recorded near the ceiling leaves almost no room: every
  # later epoch is stale or implausible, and the watermark is durable, so the wedge does
  # not clear. The register's own ceiling is the last line; this is the one in front of it,
  # and it is here rather than there because a *signature* is what makes a huge epoch
  # deployable at all — a manifest nobody signed never reaches a register.
  #
  # A million above the highest number this node knows about is generous by six orders of
  # magnitude for a counter that adds one per allocation, and it is not a bound on how many
  # deployments a cluster may do: the floor rises with them.
  #
  # Honest limit: the floor is what *this* node can see. On a dedicated `:signer` host that
  # runs no rollout register and allocates no epochs, it is zero, so the effective bound is
  # a flat million — which is still a bound, and still refuses the shapes that wedge a
  # register, but it is not a statement about the cluster's real watermark.
  @max_epoch_distance 1_000_000

  # W8. What a precompiled artifact may weigh, as a multiple of the component ceiling
  # (`:signing_max_artifact_bytes`). The same number `Ouroboros.Wasm.Bundle` derives its own
  # section cap from, for the same reason: machine code is several times the wasm it came from —
  # measured, 2.75× at the worst shape §7.3 admits and 5.3× for the small reference guest — and
  # one multiple stated in both places beats two ceilings that can disagree.
  @precompiled_multiple 8

  # The same default the service applies, so a policy invoked directly — by a test, or by
  # an operator rehearsing a decision — is held to the bound a service would have applied.
  @default_max_artifact_bytes 16 * 1024 * 1024

  @impl true
  def evaluate(%Wasm.Artifact{} = artifact, context) when is_map(context) do
    with :ok <- check_wasm_shape(artifact, context),
         :ok <- check_epoch_distance(artifact),
         :ok <- check_world(artifact),
         {:ok, recomputed} <- check_component_bytes(artifact, context),
         :ok <- check_imports(artifact),
         :ok <- check_precompiled(artifact),
         {:ok, provenance} <- check_wasm_provenance(artifact.metadata),
         {:ok, eval} <- check_wasm_eval(artifact, context),
         {:ok, start} <- check_start(artifact) do
      {:ok,
       %{
         lane: :wasm,
         epoch: artifact.epoch,
         name: artifact.name,
         kind: artifact.kind,
         world: artifact.world,
         component_sha256: artifact.component_sha256,
         size: artifact.size,
         imports: artifact.imports,
         precompiled: precompiled_verdict(artifact.precompiled),
         recomputed: recomputed,
         provenance: provenance,
         eval: eval,
         start: start
       }}
    end
  rescue
    # A refusal must never leave this process as an exception: the requester reaches it
    # through `:erpc`, and a raise there is indistinguishable from transport ambiguity.
    error -> {:refused, {:policy_exception, Exception.message(error)}}
  catch
    kind, reason -> {:refused, {:policy_failure, kind, inspect(reason)}}
  end

  def evaluate(other, context) when is_map(context),
    do: {:refused, {:invalid_artifact, describe(other)}}

  def evaluate(_artifact, context), do: {:refused, {:invalid_policy_context, describe(context)}}

  defp counter(report, key) do
    case Map.get(report, key) do
      value when is_integer(value) and value >= 0 -> value
      _other -> nil
    end
  end

  defp check_wasm_shape(%Wasm.Artifact{} = artifact, context) do
    max = max_artifact_bytes(context)

    cond do
      not is_binary(artifact.id) or artifact.id == "" ->
        {:refused, :invalid_artifact_id}

      not is_integer(artifact.epoch) or artifact.epoch <= 0 ->
        {:refused, {:invalid_epoch, describe(artifact.epoch)}}

      not Wasm.Artifact.name?(artifact.name) ->
        {:refused, {:invalid_component_name, describe(artifact.name)}}

      not Wasm.Artifact.sha256?(artifact.component_sha256) ->
        {:refused, {:invalid_component_sha256, describe(artifact.component_sha256)}}

      # W15. A closed set of two, checked here rather than assumed, because everything below
      # branches on it: the world, the eval grammar and whether a start block is legal.
      not Wasm.Artifact.kind?(artifact.kind) ->
        {:refused, {:invalid_component_kind, describe(artifact.kind)}}

      not is_integer(artifact.size) or artifact.size <= 0 ->
        {:refused, {:invalid_component_size, describe(artifact.size)}}

      artifact.size > max ->
        {:refused, {:component_too_large, artifact.size, max}}

      not is_binary(artifact.world) or artifact.world == "" ->
        {:refused, {:invalid_world, describe(artifact.world)}}

      not is_list(artifact.imports) or not Enum.all?(artifact.imports, &is_binary/1) ->
        {:refused, {:invalid_component_imports, describe(artifact.imports)}}

      not is_map(artifact.metadata) or is_struct(artifact.metadata) ->
        {:refused, :invalid_artifact_metadata}

      true ->
        :ok
    end
  end

  # Positivity is not a bound. See `@max_epoch_distance`.
  defp check_epoch_distance(%Wasm.Artifact{epoch: epoch}) do
    floor = epoch_floor()

    if epoch - floor > @max_epoch_distance,
      do: {:refused, {:epoch_too_far_ahead, epoch, floor + @max_epoch_distance}},
      else: :ok
  end

  # The highest number this node knows about, from the two places one can come from: what
  # its register has admitted, and what its own allocator has handed out. Either may be
  # unavailable — a signer node runs neither — and an unavailable one contributes zero
  # rather than an opinion.
  defp epoch_floor, do: max(registry_watermark(), allocation_watermark())

  defp registry_watermark do
    case Registry.wasm_epoch() do
      epoch when is_integer(epoch) and epoch >= 0 -> epoch
      _other -> 0
    end
  rescue
    _unavailable -> 0
  catch
    _kind, _reason -> 0
  end

  defp allocation_watermark do
    case Epoch.watermark() do
      {:ok, epoch} when is_integer(epoch) and epoch >= 0 -> epoch
      _other -> 0
    end
  rescue
    _unavailable -> 0
  catch
    _kind, _reason -> 0
  end

  # The hard rule. A world is a linker contract; certifying one this build does not
  # implement would be certifying a contract nobody on any loading node can honour.
  defp check_world(%Wasm.Artifact{world: world, kind: kind}) do
    # The world a *kind* requires, not merely a world this build implements. Both are supported
    # worlds, so comparing against a set would have signed a `:policy` manifest carrying the
    # capability world — and the loading node would then hand the helper `kind: :policy` for
    # bytes whose manifest said otherwise, which is a quarantine at best.
    if world == Wasm.world_for(kind),
      do: :ok,
      else: {:refused, {:world_not_supported, world}}
  end

  # The bytes are the request's, not the manifest's. Absent bytes are a refusal rather
  # than a pass, which is the whole difference between a signer and a rubber stamp.
  defp check_component_bytes(%Wasm.Artifact{} = artifact, context) do
    case Map.get(context, :component_bytes) do
      bytes when is_binary(bytes) and bytes != "" ->
        cond do
          byte_size(bytes) != artifact.size ->
            {:refused, {:component_manifest_mismatch, :size, byte_size(bytes), artifact.size}}

          Wasm.Artifact.digest(bytes) != artifact.component_sha256 ->
            {:refused, {:component_manifest_mismatch, :sha256}}

          true ->
            {:ok, %{sha256: :recomputed, size: :recomputed, bytes: byte_size(bytes)}}
        end

      _absent ->
        {:refused, :missing_component_bytes}
    end
  end

  # Policy, not enforcement — see the moduledoc and D5. Nothing here parses a component,
  # so a signer node with no `ouro-wasm` on it decides exactly as well as one with it.
  #
  # A duplicate is refused rather than deduplicated, because the manifest is what gets
  # signed: a list the signer silently rewrote is not the list the signature covers, and
  # `Ouroboros.Wasm.Verifier.cross_check/2` compares the *sorted list* the helper reports
  # against the *sorted list* the manifest declares. `["log", "log"]` therefore could never
  # cross-check against any helper on any node — it was a manifest signed into a permanent
  # quarantine, which is a refusal worth making at the signer instead.
  defp check_imports(%Wasm.Artifact{imports: imports}) do
    cond do
      Enum.uniq(imports) != imports ->
        {:refused, {:duplicate_component_imports, describe(duplicates(imports))}}

      true ->
        case Enum.reject(imports, &(&1 in @world_imports)) do
          [] -> :ok
          [undeclared | _rest] -> {:refused, {:import_not_in_world, undeclared}}
        end
    end
  end

  # W8, D22. The signer decides whether a manifest may authorize a node to `Component::deserialize`
  # machine code it did not produce, so the block that authorizes it is checked here rather than
  # believed: all four keys or none, a 64-hex digest, a positive size within the same ceiling the
  # component is held to, and two strings that are what a helper's `doctor` would have printed —
  # non-empty, printable, bounded. What is *not* checked is whether this signer recognises the
  # version or the triple: that is a fact about a loading node, not about the manifest, and a
  # signer refusing an artifact for a machine it is not is a signer deciding somebody else's
  # question.
  #
  # Nothing here parses the artifact, for D5's reason: the bytes travel with the bundle, the
  # loading node's helper reads the container's header, and a signer that had to map machine code
  # to sign a manifest would be running the thing this lane exists to contain.
  defp check_precompiled(%Wasm.Artifact{precompiled: nil}), do: :ok

  defp check_precompiled(%Wasm.Artifact{precompiled: block} = artifact) do
    max = @precompiled_multiple * max_artifact_bytes(%{})

    cond do
      not Wasm.Artifact.precompiled?(block) ->
        {:refused, {:invalid_precompiled, describe(block)}}

      block.sha256 == artifact.component_sha256 ->
        # The serialized form of a component is never the component: one is a wasm binary and
        # the other an object file. Equal digests mean a manifest built out of one set of bytes
        # twice, which would have a node deserializing a component as if it were machine code.
        {:refused, {:precompiled_is_the_component, block.sha256}}

      block.size > max ->
        {:refused, {:precompiled_too_large, block.size, max}}

      true ->
        :ok
    end
  end

  defp precompiled_verdict(nil), do: :absent

  defp precompiled_verdict(%{wasmtime: wasmtime, target: target, sha256: sha256, size: size}),
    do: %{wasmtime: wasmtime, target: target, sha256: sha256, size: size}

  defp duplicates(imports) do
    imports
    |> Enum.frequencies()
    |> Enum.filter(fn {_import, count} -> count > 1 end)
    |> Enum.map(&elem(&1, 0))
    |> Enum.sort()
  end

  defp check_wasm_provenance(metadata) do
    with {:ok, author} <- fetch_author(metadata),
         {:ok, source_sha256} <- fetch_optional_sha256(metadata),
         {:ok, language} <- fetch_optional_language(metadata),
         {:ok, tests} <- fetch_optional_tests(metadata) do
      {:ok,
       %{author: author, source_sha256: source_sha256, language: language, test_report: tests}}
    end
  end

  defp fetch_author(metadata) do
    case Map.get(metadata, :author) do
      author when is_binary(author) and author != "" -> {:ok, author}
      nil -> {:refused, {:provenance_missing, :author}}
      other -> {:refused, {:invalid_provenance, :author, describe(other)}}
    end
  end

  defp fetch_optional_sha256(metadata) do
    case Map.get(metadata, :source_sha256) do
      nil ->
        {:ok, nil}

      sha ->
        if is_binary(sha) and sha =~ ~r/\A[0-9a-f]{#{@sha256_hex}}\z/,
          do: {:ok, sha},
          else: {:refused, {:invalid_provenance, :source_sha256, describe(sha)}}
    end
  end

  defp fetch_optional_language(metadata) do
    case Map.get(metadata, :language) do
      nil -> {:ok, nil}
      language when is_binary(language) and language != "" -> {:ok, language}
      other -> {:refused, {:invalid_provenance, :language, describe(other)}}
    end
  end

  # Optional on purpose (D12): there is no BuildPeer here, so a guest toolchain's report is
  # provenance when it exists and never a precondition. What is checked is that a report
  # which *does* exist is not a report of failures.
  defp fetch_optional_tests(metadata) do
    case Map.get(metadata, :test_report) do
      nil ->
        {:ok, nil}

      report when is_map(report) and not is_struct(report) ->
        case counter(report, :failures) do
          nil -> {:refused, {:invalid_provenance, :test_report, describe(report)}}
          0 -> {:ok, report}
          failures -> {:refused, {:tests_failed, failures, counter(report, :total)}}
        end

      other ->
        {:refused, {:invalid_provenance, :test_report, describe(other)}}
    end
  end

  # Required by default (D12), with one branch on the kind. A
  # capability's spec is a probe list over the wrapper agent's state; a policy's is a list of
  # permission requests and the decision this component must reach about each. They are
  # different grammars because they judge different things, and validating one against the
  # other's validator would refuse every honest spec in the lane it was not written for.
  defp check_wasm_eval(%Wasm.Artifact{metadata: metadata, kind: kind}, context) do
    required? = Map.get(context, :require_wasm_eval, true) == true

    case {required?, Map.get(metadata, :eval)} do
      {false, nil} -> {:ok, :absent}
      {true, nil} -> {:refused, :eval_spec_required}
      {required?, spec} -> validated_eval(spec, kind, required?)
    end
  end

  defp validated_eval(spec, kind, required?) do
    validate =
      case kind do
        :policy -> &Wasm.PolicyEngine.validate_eval/1
        _capability -> &Evaluation.validate/1
      end

    case validate.(spec) do
      {:ok, _valid} -> {:ok, if(required?, do: :required_and_valid, else: :present)}
      # Both validators already name their failures `{:invalid_eval_spec, _}`.
      {:error, reason} -> {:refused, reason}
    end
  end

  defp check_start(%Wasm.Artifact{kind: :policy, metadata: metadata}) do
    # W15. A start block is the claim "this component runs continuously under this durable mesh
    # id". A policy component has no wrapper agent and is reached only by the permission engine,
    # so a start block on one is a claim on a cluster-wide id that nothing will ever start —
    # and an id the register would hold against a component no message can reach.
    case Map.get(metadata, :start) do
      nil -> {:ok, :absent}
      _declared -> {:refused, {:invalid_start, :policy_components_do_not_start}}
    end
  end

  defp check_start(%Wasm.Artifact{} = artifact) do
    case Map.get(artifact.metadata, :start) do
      nil -> {:ok, :absent}
      start when is_map(start) and not is_struct(start) -> validate_start(start, artifact.name)
      other -> {:refused, {:invalid_start, describe(other)}}
    end
  end

  # The id is bound to **this component's name**, not merely to the lane's prefix. A prefix
  # is a namespace, and a namespace with nothing inside it binding an id to the manifest it
  # travels in is a namespace any signed component can point anywhere in: a component named
  # `evil` declaring `start.id: "wasm/greeter"` was, before this, a perfectly signable
  # manifest whose registry entry said `wasm/evil` while the process it claimed cluster-wide
  # was the one everybody trusts as `greeter`. It also made `wasm/../../etc/passwd` and a
  # right-to-left-override id signable, neither of which is a name anybody meant.
  #
  # One name, one durable id, and the id is the register's `module` field spelled the same
  # way. `Ouroboros.Wasm.Rollout.start_block/1` and `Ouroboros.Wasm.Boot` re-derive it from
  # the manifest rather than reading it, so a reader is never the one deciding.
  #
  # There is no separate bound on the id's length any more, and there is no separate
  # `String.valid?/1` on it: both are now facts about the name, which `check_wasm_shape/2`
  # has already held to `Ouroboros.Wasm.Artifact.name?/1` — at most 64 bytes of lower-case
  # ASCII. A second bound that can never fire is a rule nobody is enforcing.
  defp validate_start(start, name) when is_binary(name) do
    id = Map.get(start, :id)
    config = Map.get(start, :config)
    expected = @start_prefix <> name

    cond do
      Map.keys(start) -- [:id, :config] != [] ->
        {:refused, {:invalid_start, :unknown_keys}}

      not is_binary(id) or id != expected ->
        {:refused, {:invalid_start_id, describe(id)}}

      not is_binary(config) ->
        {:refused, {:invalid_start, :config}}

      byte_size(config) > @max_start_config_bytes ->
        {:refused, {:invalid_start, :config_too_large}}

      true ->
        {:ok, %{id: id, config_bytes: byte_size(config)}}
    end
  end

  defp max_artifact_bytes(context) do
    case Map.get(context, :max_artifact_bytes) do
      value when is_integer(value) and value > 0 ->
        value

      _absent ->
        case Application.get_env(:ouroboros, :signing_max_artifact_bytes) do
          value when is_integer(value) and value > 0 -> value
          _unset_or_invalid -> @default_max_artifact_bytes
        end
    end
  end

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
