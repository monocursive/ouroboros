defmodule Ouroboros.Upgrade.Signing.Policy do
  @moduledoc """
  The gate a signer node applies to a full artifact *before* any signature exists.

  This is the independence the rest of the upgrade lane cannot supply for itself. The
  forge decides what to build; `Ouroboros.Upgrade.Verifier` decides what a target node
  will load. Both of those run inside the application an agent can patch. This policy
  runs in the process that holds the key, on a host whose supervision tree contains
  nothing else, and it is the only check in the system that happens while refusing is
  still free — after a signature exists, every later check is arguing with cryptography.

  ## What a policy is given, and what it trusts

  `evaluate/2` receives the **whole submitted artifact**, not the canonical payload the
  requester wants signed. That is the entire point: a payload is a hash of a manifest,
  and a manifest is a set of claims. The shipped policy recomputes every one of those
  claims from the BEAM bytes actually present — sha256, md5, module name, vsn, and the
  offline `Ouroboros.Upgrade.Beam.inspect_binary/1` gates — so a requester that
  precomputed a flattering manifest is refused on arithmetic rather than trusted.

  It trusts exactly one thing about the requester: nothing.

  ## The namespace rule is structural

  Every module in the artifact must be under `Ouroboros.Capability.`, in either
  disposition. This is not the verifier's protected-prefix list restated — that list
  names what may not be *replaced*, and is enforced on the loading node, inside the
  application. This rule is the complement, enforced here: a signer that will only ever
  sign capability modules cannot be talked into signing a control-plane patch, whatever
  the requester's argument, because it has no code path that produces that signature.

  ## What a signer cannot know

  Some checks belong to the target and are named here so nobody mistakes their absence
  for an oversight:

    * **Epoch ordering.** A signer sees a number. It has no view of any cluster's epoch
      watermark, and asking it to would make it a participant in the deployment it is
      supposed to be independent of. Only positivity is checked; monotonicity is the
      target executor's job and survives this signature entirely.
    * **Pre-image freshness for `:replace`.** Whether `old_sha256` matches what a target
      is running right now is a statement about that target's VM at load time. The
      signer checks the pre-image bytes are internally consistent — they hash to what
      the manifest claims, and carry no on-load, NIF import, or protocol marker — and
      leaves currency to `Verifier.verify/2` on the node itself.
    * **Module absence for `:introduce`.** Same reason: absence is a property of a VM.

  ## Refusals are values

  Every failure is `{:refused, reason}` with a named reason. Nothing raises across this
  boundary: an exception here would reach the requester through `:erpc` as transport
  ambiguity, and a signing service must never let "I refuse" and "I do not know what
  happened" look alike.

  ## Two lanes, one gate

  `evaluate/2` is also the gate for lane W (docs/WASM.md §7.5): an
  `Ouroboros.Wasm.Artifact` is a manifest describing WebAssembly component bytes that
  travel *beside* it, so the shipped policy dispatches on the struct. Nothing about the
  BEAM arm changes. What the two arms share is the posture — recompute every claim that
  can be recomputed, refuse outside a namespace no configuration widens — and what they
  do not share is the payload space: the two `signing_payload/2` functions carry
  different tags, so a signature over one can never be replayed as a signature over the
  other.

  ## Configuration

    * `config :ouroboros, :signing_policy` — the module implementing this behaviour,
      defaulting to `Ouroboros.Upgrade.Signing.Policy.Default`.
    * `config :ouroboros, :signing_require_eval` — when true, a BEAM artifact must carry
      a valid `Ouroboros.Upgrade.Rollout.Evaluation` spec in `metadata.forge.eval`.
      Defaults to false so the shipped behaviour is the behaviour that existed before
      this module; production deployments should set it to true, because it is the one
      switch that makes "this capability declared how it would be judged" a precondition
      of a signature rather than a hope.
    * `config :ouroboros, :signing_require_wasm_eval` — the same switch for lane W, and
      it defaults to **true**. That asymmetry is deliberate and is D12: the BEAM lane has
      a build peer that ran ExUnit and a `test_report` to show for it, and lane W has no
      analogue, so the signed eval spec *is* the test story there. The semantics extend
      rather than fork — same validator, same refusal — and only the default differs.
  """

  alias Ouroboros.Upgrade.Artifact

  @default_rate_limit_window_ms 60_000
  @default_max_requesters 64

  @typedoc "Everything the service knows about the request, and nothing about the key."
  @type context :: %{
          required(:signer_id) => String.t(),
          required(:requester) => node(),
          required(:require_eval) => boolean(),
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
  @callback evaluate(artifact :: Artifact.t() | struct(), context :: context()) ::
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
  The shipped independent gate: recompute everything, and refuse outside the namespace.

  Five families of check, in the order that refuses soonest and cheapest:

  1. **Shape.** A real `Ouroboros.Upgrade.Artifact` struct with a non-empty id, a
     positive integer epoch, a non-empty list of distinct `Ouroboros.Upgrade.Beam`
     structs, and a map for metadata. Anything else is a malformed request, not a
     policy question.
  2. **Namespace.** Every module under `Ouroboros.Capability.`, in either disposition.
     Hard: there is no configuration that widens it.
  3. **Recomputation.** For every binary in the artifact: `:beam_lib` says which module
     it is, sha256 and md5 are computed from the bytes present, `vsn` is read from the
     attributes chunk, and the code server is asked to prepare the batch so an `-on_load`
     function is detected soundly rather than looked for in a chunk it never appears in.
     Static `:erlang.load_nif/2` imports and protocol markers are refused. Every one of
     those is compared against what the manifest claimed, and a mismatch is the refusal.
     A `:replace` beam's pre-image is held to the same binary-level checks; its
     *currency* is not, because that is a fact about a target VM.
  4. **Provenance.** `metadata.forge` must exist and carry a `source_sha256` and a
     `test_report` in which nothing failed and at least one test passed. A capability
     whose tests never ran has no provenance to sign.
  5. **Evaluation criteria**, when `:signing_require_eval` is on: `metadata.forge.eval`
     must be a spec `Ouroboros.Upgrade.Rollout.Evaluation.validate/1` accepts.

  What this proves is bounded and worth stating plainly: that the bytes in front of the
  signer are internally consistent, live in the namespace this signer signs for, and
  arrived with a build report claiming green tests. It does not prove the code is good,
  that the test report describes those bytes (the forge asserts that link; the signer
  cannot re-run a build it did not perform), or that the requester is who it says it is.

  ## The lane-W arm

  An `Ouroboros.Wasm.Artifact` is checked by six families, in the order docs/WASM.md §7.5
  states them:

  1. **Shape and size.** Non-empty id and name, positive epoch, 64-hex lower-case
     `component_sha256`, positive `size` within `:signing_max_artifact_bytes` — the same
     bound the BEAM lane's submissions are held to — a string world, a list of string
     imports, a plain map for metadata.
  2. **World.** `world == Ouroboros.Wasm.world()`. This is the namespace rule's analogue
     and it is just as hard: there is no configuration that widens it. A signer that can
     be argued into signing a component for a world this build does not implement is a
     signer that has certified a linker contract nobody here can honour.
  3. **Recomputation.** The submitted component bytes arrive in `context.component_bytes`
     — the same posture as the advisory payload, supplied per request — and the sha256
     and the size are recomputed from them. Absent bytes are a refusal
     (`:missing_component_bytes`), never a pass: a manifest nobody checked against bytes
     is a set of claims, and this is the one process whose whole job is not to believe
     them.
  4. **Imports.** The declared list must be a subset of the world's, which in v1 is
     `["log"]`. This is a *policy* check and is documented as one (D5): the security
     boundary is the helper's linker, which defines exactly the world's imports and fails
     instantiation on anything undeclared. Nothing here parses the component binary, and
     nothing here needs the `ouro-wasm` helper to be present on the signer node — a
     signer that cannot parse components is still not a hole, because the list it is
     reading is provenance and review surface rather than the enforcement mechanism.
  5. **Provenance.** `metadata.author` must be present. `metadata.eval` is validated by
     `Ouroboros.Upgrade.Rollout.Evaluation.validate/1` whenever it is there, and is
     **required by default** (D12, `:signing_require_wasm_eval`). `source_sha256`,
     `language`, and `test_report` are optional and are checked for shape when present:
     a guest toolchain that produces a test report is welcome to say so, and lane W does
     not pretend one exists when it does not.
  6. **Start block.** `metadata.start`, when present, must be exactly
     `%{id: binary, config: binary}` with the id under the `wasm/` prefix. It is the
     claim "this capability runs continuously under this id", which a signature should
     cover and which a manifest must not be able to point at another lane's namespace.
  """

  @behaviour Ouroboros.Upgrade.Signing.Policy

  alias Ouroboros.Upgrade.{Artifact, Beam}
  alias Ouroboros.Upgrade.Rollout.Evaluation
  alias Ouroboros.Wasm

  @capability_prefix "Elixir.Ouroboros.Capability."
  @sha256_hex 64
  @max_reported_modules 25

  # v1's world imports exactly one function (docs/WASM.md §7.1). Growth of this set is a
  # signing-policy event, which is why the list is here and not in configuration.
  @world_imports ["log"]

  # The namespace a lane-W durable agent id lives in. `Ouroboros.Wasm.Rollout` writes the
  # registry entry's module as `"wasm/" <> name` for the same reason.
  @start_prefix "wasm/"
  @max_start_id_bytes 256
  @max_start_config_bytes 16_384

  # The same default the service applies, so a policy invoked directly — by a test, or by
  # an operator rehearsing a decision — is held to the bound a service would have applied.
  @default_max_artifact_bytes 16 * 1024 * 1024

  @impl true
  def evaluate(%Artifact{} = artifact, context) when is_map(context) do
    with :ok <- check_shape(artifact),
         :ok <- check_namespace(artifact.modules),
         {:ok, modules} <- recompute(artifact.modules),
         {:ok, provenance} <- check_provenance(artifact.metadata),
         {:ok, eval} <- check_eval(artifact.metadata, context) do
      {:ok,
       %{
         epoch: artifact.epoch,
         namespace: :ouroboros_capability,
         recomputed: length(modules),
         modules: Enum.take(modules, @max_reported_modules),
         provenance: provenance,
         eval: eval
       }}
    end
  rescue
    # A malformed binary can make `:beam_lib` unhappy in ways its own error tuples do not
    # cover. That is a refusal; it must never leave this process as an exception, because
    # the requester reaches it through `:erpc` and would read a raise as ambiguity.
    error -> {:refused, {:policy_exception, Exception.message(error)}}
  catch
    kind, reason -> {:refused, {:policy_failure, kind, inspect(reason)}}
  end

  # Lane W. Same posture, different arithmetic: there are no BEAM binaries to inspect and
  # no module names to namespace, so what is recomputed is the digest and the size of the
  # component bytes submitted beside the manifest, and the hard rule is the world.
  def evaluate(%Wasm.Artifact{} = artifact, context) when is_map(context) do
    with :ok <- check_wasm_shape(artifact, context),
         :ok <- check_world(artifact),
         {:ok, recomputed} <- check_component_bytes(artifact, context),
         :ok <- check_imports(artifact),
         {:ok, provenance} <- check_wasm_provenance(artifact.metadata),
         {:ok, eval} <- check_wasm_eval(artifact.metadata, context),
         {:ok, start} <- check_start(artifact.metadata) do
      {:ok,
       %{
         lane: :wasm,
         epoch: artifact.epoch,
         name: artifact.name,
         world: artifact.world,
         component_sha256: artifact.component_sha256,
         size: artifact.size,
         imports: artifact.imports,
         recomputed: recomputed,
         provenance: provenance,
         eval: eval,
         start: start
       }}
    end
  rescue
    # Same reason as the BEAM arm: the requester reaches this through `:erpc`, and a raise
    # there is indistinguishable from transport ambiguity.
    error -> {:refused, {:policy_exception, Exception.message(error)}}
  catch
    kind, reason -> {:refused, {:policy_failure, kind, inspect(reason)}}
  end

  def evaluate(other, context) when is_map(context),
    do: {:refused, {:invalid_artifact, describe(other)}}

  def evaluate(_artifact, context), do: {:refused, {:invalid_policy_context, describe(context)}}

  defp check_shape(%Artifact{} = artifact) do
    modules = artifact.modules

    cond do
      not is_binary(artifact.id) or artifact.id == "" ->
        {:refused, :invalid_artifact_id}

      not is_integer(artifact.epoch) or artifact.epoch <= 0 ->
        {:refused, {:invalid_epoch, describe(artifact.epoch)}}

      not is_list(modules) or modules == [] ->
        {:refused, :empty_artifact}

      not Enum.all?(modules, &match?(%Beam{}, &1)) ->
        {:refused, :invalid_artifact_modules}

      modules |> Enum.map(& &1.module) |> Enum.uniq() |> length() != length(modules) ->
        {:refused, :duplicate_modules}

      not is_map(artifact.metadata) ->
        {:refused, :invalid_artifact_metadata}

      true ->
        :ok
    end
  end

  # The one rule with no configuration behind it. A signer that can be argued into the
  # control plane is a signer that adds nothing.
  defp check_namespace(modules) do
    Enum.reduce_while(modules, :ok, fn beam, :ok ->
      if String.starts_with?(Atom.to_string(beam.module), @capability_prefix) do
        {:cont, :ok}
      else
        {:halt, {:refused, {:module_outside_capability_namespace, beam.module}}}
      end
    end)
  end

  defp recompute(modules) do
    Enum.reduce_while(modules, {:ok, []}, fn beam, {:ok, acc} ->
      case recompute_module(beam) do
        {:ok, summary} -> {:cont, {:ok, [summary | acc]}}
        {:refused, _reason} = refusal -> {:halt, refusal}
      end
    end)
    |> case do
      {:ok, summaries} -> {:ok, Enum.reverse(summaries)}
      refusal -> refusal
    end
  end

  defp recompute_module(%Beam{disposition: disposition} = beam)
       when disposition in [:replace, :introduce] do
    with :ok <- check_disposition_shape(beam),
         :ok <- check_binary(beam.module, beam.binary, beam.sha256, beam.md5, beam.vsn, :new),
         :ok <- check_preimage(beam) do
      {:ok, %{module: beam.module, disposition: disposition, sha256: beam.sha256}}
    end
  end

  defp recompute_module(%Beam{} = beam),
    do: {:refused, {:invalid_disposition, beam.module, describe(beam.disposition)}}

  # An `:introduce` beam has nothing to migrate and nothing to roll back to. A
  # `:replace` beam must carry the pre-image the manifest describes, or the signature
  # would cover a rollback path that does not exist.
  defp check_disposition_shape(%Beam{disposition: :introduce} = beam) do
    if is_nil(beam.old_binary) and is_nil(beam.old_sha256) and is_nil(beam.old_md5) and
         is_nil(beam.old_vsn) and is_nil(beam.old_filename) and beam.stateful == false and
         is_nil(beam.migration_extra) do
      :ok
    else
      {:refused, {:invalid_introduction, beam.module}}
    end
  end

  defp check_disposition_shape(%Beam{disposition: :replace} = beam) do
    cond do
      not is_binary(beam.old_binary) ->
        {:refused, {:missing_preimage, beam.module}}

      not is_boolean(beam.stateful) ->
        {:refused, {:invalid_stateful_declaration, beam.module}}

      not Beam.portable_term?(beam.migration_extra) ->
        {:refused, {:invalid_migration_extra, beam.module}}

      not beam.stateful and not is_nil(beam.migration_extra) ->
        {:refused, {:migration_extra_for_stateless_module, beam.module}}

      true ->
        :ok
    end
  end

  defp check_preimage(%Beam{disposition: :introduce}), do: :ok

  defp check_preimage(%Beam{disposition: :replace} = beam) do
    check_binary(beam.module, beam.old_binary, beam.old_sha256, beam.old_md5, beam.old_vsn, :old)
  end

  defp check_binary(module, binary, sha256, md5, vsn, which) when is_binary(binary) do
    case Beam.inspect_binary(binary) do
      {:ok, info} ->
        cond do
          info.module != module ->
            {:refused, {:module_mismatch, module, info.module, which}}

          Beam.sha256(binary) != sha256 ->
            {:refused, {:manifest_mismatch, module, :sha256, which}}

          info.md5 != md5 ->
            {:refused, {:manifest_mismatch, module, :md5, which}}

          info.vsn != vsn ->
            {:refused, {:manifest_mismatch, module, :vsn, which}}

          info.on_load? ->
            {:refused, {:forbidden_beam_feature, module, :on_load, which}}

          info.nif? ->
            {:refused, {:forbidden_beam_feature, module, :nif, which}}

          info.protocol? ->
            {:refused, {:forbidden_beam_feature, module, :protocol, which}}

          true ->
            :ok
        end

      {:error, reason} ->
        {:refused, {:invalid_beam, module, describe(reason), which}}
    end
  end

  defp check_binary(module, _binary, _sha256, _md5, _vsn, which),
    do: {:refused, {:missing_beam_binary, module, which}}

  defp check_provenance(metadata) do
    with {:ok, forge} <- fetch_forge(metadata),
         {:ok, source_sha256} <- fetch_source_sha256(forge),
         {:ok, tests} <- fetch_test_report(forge) do
      {:ok,
       %{
         source_sha256: source_sha256,
         author: author(forge),
         tests: tests
       }}
    end
  end

  defp fetch_forge(metadata) do
    case Map.get(metadata, :forge) do
      forge when is_map(forge) and not is_struct(forge) -> {:ok, forge}
      nil -> {:refused, {:provenance_missing, :forge}}
      other -> {:refused, {:invalid_provenance, :forge, describe(other)}}
    end
  end

  defp fetch_source_sha256(forge) do
    case Map.get(forge, :source_sha256) do
      sha when is_binary(sha) and byte_size(sha) == @sha256_hex ->
        if sha =~ ~r/\A[0-9a-f]{#{@sha256_hex}}\z/ do
          {:ok, sha}
        else
          {:refused, {:invalid_provenance, :source_sha256, describe(sha)}}
        end

      nil ->
        {:refused, {:provenance_missing, :source_sha256}}

      other ->
        {:refused, {:invalid_provenance, :source_sha256, describe(other)}}
    end
  end

  # `passed` is derived rather than read: the sandbox reports totals and exclusions, and
  # a report that "passed" only because every test was excluded is not a green build.
  defp fetch_test_report(forge) do
    case Map.get(forge, :test_report) do
      report when is_map(report) and not is_struct(report) ->
        total = counter(report, :total)
        failures = counter(report, :failures)
        excluded = counter(report, :excluded)
        skipped = counter(report, :skipped)
        passed = passed(report, total, failures, excluded, skipped)

        cond do
          is_nil(total) or is_nil(failures) ->
            {:refused, {:invalid_provenance, :test_report, describe(report)}}

          failures > 0 ->
            {:refused, {:tests_failed, failures, total}}

          passed < 1 ->
            {:refused, {:no_tests_passed, total, passed}}

          true ->
            {:ok,
             %{
               total: total,
               failures: failures,
               excluded: excluded || 0,
               skipped: skipped || 0,
               passed: passed
             }}
        end

      nil ->
        {:refused, {:provenance_missing, :test_report}}

      other ->
        {:refused, {:invalid_provenance, :test_report, describe(other)}}
    end
  end

  defp passed(report, total, failures, excluded, skipped) do
    case Map.get(report, :passed) do
      passed when is_integer(passed) and passed >= 0 ->
        passed

      _absent ->
        if is_nil(total) or is_nil(failures) do
          0
        else
          max(total - failures - (excluded || 0) - (skipped || 0), 0)
        end
    end
  end

  defp counter(report, key) do
    case Map.get(report, key) do
      value when is_integer(value) and value >= 0 -> value
      _other -> nil
    end
  end

  defp author(forge) do
    case Map.get(forge, :author) do
      author when is_binary(author) -> author
      _other -> nil
    end
  end

  defp check_eval(metadata, context) do
    required? = Map.get(context, :require_eval, false) == true
    spec = metadata |> Map.get(:forge, %{}) |> eval_spec()

    case {required?, spec} do
      {false, :absent} ->
        {:ok, :absent}

      {false, {:present, spec}} ->
        case Evaluation.validate(spec) do
          {:ok, _valid} -> {:ok, :present}
          # `Evaluation.validate/1` already names its failures `{:invalid_eval_spec, _}`;
          # wrapping them again would only bury the reason one tuple deeper.
          {:error, reason} -> {:refused, reason}
        end

      {true, :absent} ->
        {:refused, :eval_spec_required}

      {true, {:present, spec}} ->
        case Evaluation.validate(spec) do
          {:ok, _valid} -> {:ok, :required_and_valid}
          # `Evaluation.validate/1` already names its failures `{:invalid_eval_spec, _}`;
          # wrapping them again would only bury the reason one tuple deeper.
          {:error, reason} -> {:refused, reason}
        end
    end
  end

  defp eval_spec(forge) when is_map(forge) do
    case Map.fetch(forge, :eval) do
      {:ok, nil} -> :absent
      {:ok, spec} -> {:present, spec}
      :error -> :absent
    end
  end

  defp eval_spec(_forge), do: :absent

  ## Lane W

  defp check_wasm_shape(%Wasm.Artifact{} = artifact, context) do
    max = max_artifact_bytes(context)

    cond do
      not is_binary(artifact.id) or artifact.id == "" ->
        {:refused, :invalid_artifact_id}

      not is_integer(artifact.epoch) or artifact.epoch <= 0 ->
        {:refused, {:invalid_epoch, describe(artifact.epoch)}}

      not is_binary(artifact.name) or artifact.name == "" ->
        {:refused, {:invalid_component_name, describe(artifact.name)}}

      not Wasm.Artifact.sha256?(artifact.component_sha256) ->
        {:refused, {:invalid_component_sha256, describe(artifact.component_sha256)}}

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

  # The lane-W analogue of the capability namespace, and hard for the same reason. A world
  # is a linker contract; certifying one this build does not implement would be certifying
  # a contract nobody on any loading node can honour.
  defp check_world(%Wasm.Artifact{world: world}) do
    if world == Wasm.world(), do: :ok, else: {:refused, {:world_not_supported, world}}
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
  defp check_imports(%Wasm.Artifact{imports: imports}) do
    case Enum.reject(imports, &(&1 in @world_imports)) do
      [] -> :ok
      [undeclared | _rest] -> {:refused, {:import_not_in_world, undeclared}}
    end
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

  # Same validator and same refusal as the BEAM arm; only the default of the switch
  # differs, and the moduledoc says why.
  defp check_wasm_eval(metadata, context) do
    required? = Map.get(context, :require_wasm_eval, true) == true

    case {required?, Map.get(metadata, :eval)} do
      {false, nil} -> {:ok, :absent}
      {true, nil} -> {:refused, :eval_spec_required}
      {required?, spec} -> validated_eval(spec, required?)
    end
  end

  defp validated_eval(spec, required?) do
    case Evaluation.validate(spec) do
      {:ok, _valid} -> {:ok, if(required?, do: :required_and_valid, else: :present)}
      # `Evaluation.validate/1` already names its failures `{:invalid_eval_spec, _}`.
      {:error, reason} -> {:refused, reason}
    end
  end

  defp check_start(metadata) do
    case Map.get(metadata, :start) do
      nil -> {:ok, :absent}
      start when is_map(start) and not is_struct(start) -> validate_start(start)
      other -> {:refused, {:invalid_start, describe(other)}}
    end
  end

  defp validate_start(start) do
    id = Map.get(start, :id)
    config = Map.get(start, :config)

    cond do
      Map.keys(start) -- [:id, :config] != [] ->
        {:refused, {:invalid_start, :unknown_keys}}

      not is_binary(id) or not String.starts_with?(id, @start_prefix) or
          byte_size(id) <= byte_size(@start_prefix) ->
        {:refused, {:invalid_start_id, describe(id)}}

      byte_size(id) > @max_start_id_bytes or not String.valid?(id) ->
        {:refused, {:invalid_start_id, :bounds}}

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
