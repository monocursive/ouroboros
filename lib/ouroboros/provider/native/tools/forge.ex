defmodule Ouroboros.Provider.Native.Tools.Forge do
  @moduledoc """
  Build, sign and deploy a lane-W WebAssembly capability from inside a model turn
  (docs/SELF.md §S1, docs/WASM.md §7.7).

  `Tools.Capability` was the seam that let a model *reach* a component somebody else had
  deployed. This is the other half: the seam that lets a session produce one. It is the
  shortest path from a model's turn to the runtime that turn is running in, and every
  sentence below is about keeping that path inside fences that already existed rather than
  building it new ones.

  ## What it is not

  **Not a build service.** Everything a project may contain, weigh, link against and read
  is `Ouroboros.Wasm.Forge`'s contract C9 — thirty-two files, a mebibyte, `Cargo.toml`,
  `Cargo.lock`, `README.md`, `manifest.json` and `src/**.rs` and nothing else, no
  `build.rs`, no symlink followed, the lock pinned byte-for-byte to the SDK's, the build
  itself offline under this node's OS sandbox. This module adds not one byte of leniency to
  that list; it resolves a path, reads a manifest, and calls it.

  **Not a deploy verb.** `deploy` ships one bundle *this session forged*, to this node,
  and nothing else. The operator's verbs — `capabilities.admit`, `wasm.deploy`, a rollout
  aimed at a fleet — stay where they are, under an operator's scope.

  ## The four things that make it honest

  **`author` is the principal, and is not reachable from the model.** The loop hands this
  tool `principal: principal(state)` and this module reads that and nothing else. `author`
  is not in the schema, so `Tools.atomize/2` drops a supplied one before
  `validate_params/1` sees it — but the guarantee does not rest on that: a parameter of
  that name is never read here. A context whose principal is absent, is not a binary, or
  is the loop's anonymous `"native"` fallback is a refusal, because `"native"` is not an
  identity — it is every unidentified session at once, and `deploy` is gated on the author
  matching, so a shared bucket there would be one session deploying another's bytes.

  **`name` is checked on the exact bytes and passed on unchanged.** The F1 rule from
  `Tools.Capability.resolve/1`: `Ouroboros.Provider.Native.Tools.classify/3` puts the name
  in the permission request's context only when `Ouroboros.Wasm.Artifact.name?/1` accepts
  it, and this module hands the *same string* to `Wasm.Forge`, which refuses a `Cargo.toml`
  whose package is called anything else. Nothing here trims, strips or folds. A capability
  has no register entry before it exists, so what makes `Forge(<name>)` an honest allow is
  not a lookup — it is that the forge is held to the name the engine was shown.

  A `deploy` names an artifact id rather than a name, and it carries a name to the engine
  all the same — the one that id *resolves to* (Q-B). `Tools.classify/3` reads the bundle
  out of this node's forged ring, decodes it, and verifies its signed manifest against this
  node's trust policy — the check `Ouroboros.Wasm.PolicyEngine` makes before loading a byte
  — and requires the kind to be `:capability` before any name reaches the engine. So one
  `Forge(vet)` rule covers building `vet` and deploying `vet`, which is the sentence
  somebody answering that prompt meant, and what it does *not* cover is anything else that
  id might resolve to: `deploy/3` re-reads the same bundle, re-verifies it, and refuses
  unless the kind, the author and the name all still hold — the name against what the
  engine was actually shown, which the loop hands back to the tool as
  `forge_evaluated_name`. A `status` names nothing.

  **`path` is the session's own workspace, and it is declared.** Resolved through
  `Ouroboros.Provider.Native.Paths.resolve/2` with the session's scope, the same
  containment `read` uses, before `Wasm.Forge` is told a directory exists — and put in the
  permission request's `paths`, because a `preview` reads every file in that directory. A
  `Read` rule that denies or asks therefore covers a forge of it; an allow `Read` rule does
  not make a forge an allow.

  **The ledger is the gate, not the log, and an entry is never left to nobody.** A `:forge`
  or `:deploy` entry is written under the session principal *before* the effect and settled
  after, exactly as `Ouroboros.Agent.Effects.Runner` does it, and a ledger that cannot
  record refuses the operation. The three ways a settle can fail to run are closed the way
  the runner closes them: a raise or a throw settles `:failed` with the class and is
  re-raised; a brutal kill at the loop's tool timeout is caught by the ledger's own runner
  monitor (`watch_runner/3`, attached before the effect starts) and settles `:ambiguous`.
  `preview` gets no entry of its own — the ledger has no kind for it, and
  `Ouroboros.Agent.EffectLedger` is not this slice's file — so what accounts for a preview
  is its `:tool_call` entry, which every tool call has.

  ### What `authority` says, and what it cannot

  A tool is handed `scope`, `principal` and no permission decision, so the `authority` on
  these entries is an honest statement of *class* — this ran because the native loop
  admitted the call — and never a rule id this module did not see. The chain to the actual
  decision runs through `cause`: it names the `:tool_call` ledger entry for this call, whose
  own `attempt.permission_entry_id` names the `:permission` entry. Two hops, each one
  written by the thing that knew the fact.

  Neither hop depends on this node's audit stream. The loop puts that `:tool_call` entry's
  id on the tool context as `ledger_effect_id`, plainly and beside `principal`, because the
  entry itself is written on every admitted call whether or not audit is on; the audit
  fields are read only as a fallback for a caller that assembles a context the old way.

  ## Visibility

  The spec and the lookup exist only while `config :ouroboros, :native_forge_tool` is
  `true` (default `false`, set by the `self` posture). Off, the model is not taught the
  name and `Tools.lookup/3` answers `:unknown_tool` — the posture `capability` already
  takes, for the same reason: a name a model is taught and cannot use
  costs a call to discover. `Ouroboros.Audit.tool_supported?/1` does not list `forge`, so a
  node under required audit refuses it by omission.

  ## The two seams, named

  `:forge_module` (default `Ouroboros.Wasm.Forge`) and `:forge_tool_ledger` (default
  `Ouroboros.Agent.EffectLedger`) are read from application environment. They are node
  configuration in the same sense `:permissions_engine` and `:permissions_ledger` are —
  an operator's key, never a session's — and they are what lets a test prove that the
  forge is not reached (an out-of-workspace path, a refused ledger) rather than only that
  it refused.
  """

  require Logger

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Runtime.Capabilities
  alias Ouroboros.Upgrade.Rollout.Probe
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Bundle
  alias Ouroboros.Wasm.Verifier

  use Jido.Action,
    name: "forge",
    description:
      "Build, sign and deploy a WebAssembly capability this node will then run as a " <>
        "`wasm/<name>` agent, from a Rust project in this workspace. `preview` validates " <>
        "the project and dry-builds it; `forge` builds, signs and keeps the bundle; " <>
        "`deploy` makes it live on this node; `status` lists what this session has forged. " <>
        "Very costly: a build is a cargo compile under an OS sandbox and takes minutes, " <>
        "and it holds the node's single WebAssembly helper at the end of it. Always " <>
        "`preview` before `forge`. Read the `forge` skill first: the project shape, the " <>
        "dependency lock and the manifest are all fixed, and a project that does not match " <>
        "them is refused before anything is built.",
    schema: [
      operation: [
        type: :string,
        required: true,
        doc: "preview, forge, deploy or status."
      ],
      name: [
        type: :string,
        default: "",
        doc:
          "For preview and forge: the capability's name. Must equal the Cargo package name " <>
            "and the manifest's, exactly."
      ],
      path: [
        type: :string,
        default: "",
        doc: "For preview and forge: the project directory, inside this workspace."
      ],
      artifact_id: [
        type: :string,
        default: "",
        doc: "For deploy: the artifact id a forge answered with."
      ],
      eval: [
        type: :any,
        default: nil,
        doc:
          "For forge: the evaluation spec the signer requires, as a JSON object. Taken " <>
            "from the project's manifest.json when absent."
      ],
      start_config: [
        type: :string,
        default: "",
        doc:
          "For forge: the JSON string the capability is initialised with. Taken from the " <>
            "project's manifest.json when absent."
      ]
    ]

  @doc """
  The schema the model is shown.

  Hand-written for `Tools.Capability`'s reason and nothing else: `eval` is `type: :any` in
  the action schema, because an evaluation spec is a JSON object with string keys and
  NimbleOptions' `:map` accepts atom keys only — and Jido's bridge renders `:any` as
  `string`, which would have told every model to send its spec as an encoded string. A
  string there is not the object `Ouroboros.Upgrade.Rollout.Evaluation.validate/1` reads,
  and the forge would refuse it.
  """
  @spec model_schema() :: map()
  def model_schema do
    %{
      "type" => "object",
      "properties" => %{
        "operation" => %{
          "type" => "string",
          "enum" => ["preview", "forge", "deploy", "status"],
          "description" =>
            "preview: validate the project and dry-build it, changing nothing. " <>
              "forge: build, sign and keep the bundle. deploy: make a forged bundle live " <>
              "on this node. status: what this session has forged, and where it stands."
        },
        "name" => %{
          "type" => "string",
          "description" =>
            "For preview and forge: the capability's name. Lowercase letters, digits, " <>
              "`.`, `-` and `_`, starting with a letter or digit, at most 64 bytes. It " <>
              "must be exactly the Cargo package name and exactly the manifest.json name."
        },
        "path" => %{
          "type" => "string",
          "description" =>
            "For preview and forge: the project directory, relative to the workspace or " <>
              "absolute inside it."
        },
        "artifact_id" => %{
          "type" => "string",
          "description" => "For deploy: the artifact id the forge answered with."
        },
        "eval" => %{
          "type" => "object",
          "description" =>
            "For forge: the evaluation spec, as a JSON object with `probes`, `budget_ms` " <>
              "and `required`. Omit it to use the project's manifest.json."
        },
        "start_config" => %{
          "type" => "string",
          "description" =>
            "For forge: the JSON string the capability's `init` receives. Omit it to use " <>
              "the project's manifest.json."
        }
      },
      "required" => ["operation"],
      "additionalProperties" => false
    }
  end

  # The lane's agent id prefix, and the string a `:forge` ledger attempt names a module by.
  # `Ouroboros.Wasm.Rollout` owns the constant; it is restated here rather than imported for
  # `Tools.Capability`'s reason — that module belongs to another lane and this is one short
  # literal, checked against the forge's own answer on every path below.
  @prefix "wasm/"

  # The operator's own proposal metadata, beside the project and outside the build
  # (`Ouroboros.Runtime.Capabilities`, `Wasm.Forge`'s C9 allow-list). One format for the
  # operator's `capabilities.admit` and for this tool.
  @proposal_file "manifest.json"

  # `manifest.json` is metadata: a name, a sentence, an evaluation spec and a config string
  # bounded at 16 KiB by `Runtime.Capabilities`. This is the bound on the file before it is
  # parsed at all, well under the forge's own per-input mebibyte.
  @max_manifest_bytes 64 * 1024

  # The loop's principal for a session that has no id of its own. Not an identity: every
  # such session is this one string, and `deploy` compares authors.
  @anonymous "native"

  # `Ouroboros.Wasm.Rollout.deploy/4`'s two per-node deadlines that are plain defaults rather
  # than functions or configuration (`rollout.ex`, `@default_stage_timeout_ms` and
  # `@default_start_timeout_ms`). Restated here rather than imported because they are that
  # module's private constants; they are the *documented* option defaults, and this is a
  # ceiling rather than a deadline — a term that drifted downstream makes this number larger
  # than it needs to be, never smaller than what it bounds.
  @rollout_stage_timeout_ms 60_000
  @rollout_start_timeout_ms 15_000

  # What is left over: the scheduler, the epoch allocation, the bundle write, the register
  # checkpoint, and a loaded machine. Slack over a sum of real deadlines, not a bound of its
  # own.
  @timeout_margin_ms 30_000

  # What a `status` listing spends. The ring holds eight bundles; each is read whole to be
  # decoded, so this is also the bound on what one listing reads off the disk.
  @max_listed 8

  # How much of a failed build's compiler output a preview spends. The forge does not bound
  # it — for an operator reading `capabilities.preview` the whole of it is the answer — and a
  # model's turn is not that surface.
  @max_build_output_bytes 8 * 1024

  # An artifact id, the charset `Wasm.Forge` files a bundle under. Checked here before a
  # path is built from it: this is the one place a model-supplied string reaches a filename.
  @artifact_id ~r/\A[A-Za-z0-9_-]{1,64}\z/

  @doc """
  Whether this node shows and resolves the tool at all.

  Exactly `true`, never merely truthy: a key set to a string or a number is a
  misconfiguration, and the reading of a misconfigured switch that widens what a session
  can do is the one that leaves it shut.
  """
  @spec enabled?() :: boolean()
  def enabled?, do: Application.get_env(:ouroboros, :native_forge_tool) == true

  @doc """
  The longest a `forge` call can take, for the loop's own tool timeout.

  A backstop and not a deadline: every term below is a bound something else already
  enforces, and the loop's job is only to not kill the tool task while one of them is still
  legitimately running. The forge stops its own build; a loop that killed the task first
  would report a timeout for work that was inside the bound it was given, and would leave
  the `:forge` ledger entry to the runner watch rather than to a settle.

  The sum, term by term, each one read from the thing that enforces it:

    * `Ouroboros.Wasm.Forge.build_timeout/1` — the cargo build, and the deadline
      `Ouroboros.Provider.Native.Exec` signals the sandboxed process group at. Minutes; every
      other term is seconds.
    * `config :ouroboros, :signing_call_timeout` — the `:erpc` deadline on the signature
      (`Ouroboros.Upgrade.Forge.Signer`, default 15 s).
    * `config :ouroboros, :capability_eval_timeout` — the rollout's per-node `eval_timeout`
      (`Ouroboros.Wasm.Rollout.deploy/4`, default 30 s).
    * the rollout's other three per-node deadlines: `stage_timeout` (60 s),
      `probe_timeout` (`Ouroboros.Upgrade.Rollout.Probe.budget_ms/0`) and `start_timeout`
      (15 s).
    * #{@timeout_margin_ms} ms of margin for everything that is not individually bounded —
      the epoch allocation, the bundle write, the register checkpoint, scheduler delay on a
      loaded host.

  One number for four operations, because `execute_timeout/3` is a table on the tool name
  and not on the operation: a `forge` spends the first two terms and a `deploy` the rest,
  and the ceiling has to cover whichever one this call is.
  """
  @spec max_timeout_ms() :: pos_integer()
  def max_timeout_ms do
    build_timeout() + signing_timeout() + eval_timeout() + @rollout_stage_timeout_ms +
      Probe.budget_ms() + @rollout_start_timeout_ms + @timeout_margin_ms
  end

  defp signing_timeout do
    case Application.get_env(:ouroboros, :signing_call_timeout, 15_000) do
      ms when is_integer(ms) and ms > 0 -> ms
      _invalid -> 15_000
    end
  end

  defp eval_timeout do
    case Application.get_env(:ouroboros, :capability_eval_timeout, 30_000) do
      ms when is_integer(ms) and ms > 0 -> ms
      _invalid -> 30_000
    end
  end

  @doc """
  The name this call puts in the permission request's context, or `nil`.

  The F1 rule. `Ouroboros.Provider.Native.Tools.classify/3` calls this with the exact
  strings the model wrote, and `run/2` is given the same `name` a moment later and hands it
  to `Ouroboros.Wasm.Forge`, which refuses a project whose package is called anything else.
  Nothing here trims: a name padded with a non-breaking space is not a capability name, so
  the engine is told nothing rather than told something that is almost true.

  `nil` for every operation that does not pass a name on. See the moduledoc. This is the one
  place that decides *which* operations those are: `request_context/1` splits `deploy` off
  first, because a deploy's name is resolved rather than written, and asks this about
  everything else rather than keeping a second list of operation names beside it.
  """
  @spec request_name(term(), term()) :: String.t() | nil
  def request_name(operation, name) when operation in ["preview", "forge"] do
    if Artifact.name?(name), do: name, else: nil
  end

  def request_name(_operation, _name), do: nil

  @impl true
  def run(params, context) do
    case operation(params) do
      "preview" ->
        admitted(params, context, &preview/3)

      "forge" ->
        admitted(params, context, &forge/3)

      "deploy" ->
        admitted(params, context, &deploy/3)

      "status" ->
        admitted(params, context, &status/3)

      other ->
        error(
          ~s(`operation` must be "preview", "forge", "deploy" or "status", ) <>
            "got #{inspect(other)}"
        )
    end
  rescue
    # A forge a model can crash the turn with is a forge that is not contained.
    error -> error("forge failed: #{Exception.message(error)}")
  catch
    kind, reason -> error("forge failed: #{kind} #{inspect(reason, limit: 5)}")
  end

  @doc """
  The operation this call names, exactly as it was written.

  `" forge "` is not `"forge"`, for `Tools.Capability`'s reason: a tool that repaired one
  into the other would behave by a normalisation the permission engine never performed.

  Public because the classifier reads it too, and it must read it the *same way* (LOW-6).
  `Ouroboros.Provider.Native.Tools.classify/3` sees the model's JSON, whose keys are strings;
  `run/2` sees what `Tools.atomize/2` left, whose keys are atoms. A map carrying both — a
  caller assembling one by hand — used to be judged as one operation by the classifier and
  executed as another by the tool, because the two disagreed about which spelling wins. There
  is now one reader, `param/2`, string key first, and both seams call it.
  """
  @spec operation(map()) :: term()
  def operation(params) when is_map(params), do: param(params, :operation)
  def operation(_params), do: nil

  @doc """
  The permission request's context for one forge call: `%{forge: name}` or `%{}`.

  Called by `Ouroboros.Provider.Native.Tools.classify/3`, and the whole of what a `Forge(…)`
  rule matches on. Total by construction — a classifier that raised would refuse a call the
  engine never judged — so everything below answers `%{}` rather than an error.

  Three shapes:

    * `preview` and `forge` carry the `name` parameter when
      `Ouroboros.Wasm.Artifact.name?/1` accepts the exact bytes of it. `run/2` hands those
      same bytes to `Ouroboros.Wasm.Forge`, which refuses a project whose Cargo package is
      called anything else — so the allow is honest not because a name was looked up but
      because the forge is *held* to the one the engine was shown.

    * `deploy` carries the name of the bundle its `artifact_id` actually resolves to (Q-B).
      This node's forged ring is read, the bundle decoded, and its manifest verified against
      this node's own trust policy exactly as `Ouroboros.Wasm.PolicyEngine` verifies one
      before loading a byte; the kind must be `:capability`. Only then is the name put in
      front of the engine, so `Forge(vet)` covers deploying `vet` and nothing else. The
      *author* is not checked here — the classifier is not given a principal — and `deploy/3`
      checks it, along with all three of these again on the bytes as they are at that moment.

    * `status` carries nothing. It names nothing and builds nothing.
  """
  @spec request_context(map()) :: map()
  def request_context(input) when is_map(input) do
    operation = operation(input)

    case operation do
      # The one operation whose name is not a parameter: it is resolved, and `request_name/2`
      # has nothing to say about it.
      "deploy" ->
        deploy_context(param(input, :artifact_id))

      _named ->
        case request_name(operation, param(input, :name)) do
          name when is_binary(name) -> %{forge: name}
          nil -> %{}
        end
    end
  rescue
    _error -> %{}
  catch
    _kind, _reason -> %{}
  end

  def request_context(_input), do: %{}

  # The bundle as it is on disk right now, judged the way this node judges any signed
  # manifest before it acts on one. A refusal here is silence — `%{}` — and not a message:
  # the classifier's answer is what a rule matches, and "no rule covers this" is what an
  # unresolvable id should mean. The refusal a *model* reads comes from `deploy/3`.
  defp deploy_context(artifact_id) do
    with :ok <- artifact_id?(artifact_id),
         {:ok, %Artifact{kind: :capability, name: name}} <- resolve_bundle(artifact_id),
         true <- Artifact.name?(name) do
      %{forge: name}
    else
      _unresolved -> %{}
    end
  end

  # Every operation needs an identity to record against, and `forge` needs one to sign into
  # a manifest. There is exactly one source for it and it is not a parameter.
  defp admitted(params, context, fun) do
    case principal(context) do
      {:ok, principal} -> fun.(params, context, principal)
      {:refused, result} -> {:ok, result}
    end
  end

  defp principal(context) do
    case Map.get(context, :principal) do
      principal when is_binary(principal) and principal != "" and principal != @anonymous ->
        {:ok, principal}

      _absent ->
        refuse(
          "this call carries no session principal, so nothing it produced could be " <>
            "attributed to anybody. A forged capability's author is the session that " <>
            "forged it, and a deploy is refused unless the author matches; there is no " <>
            "anonymous author to fall back to. Nothing was built."
        )
    end
  end

  # ── preview ────────────────────────────────────────────────────────────────────────

  defp preview(params, context, _principal) do
    with {:ok, name} <- name(params),
         {:ok, dir} <- directory(params, context),
         {:ok, proposal} <- proposal(dir, name, params) do
      case forge_module().preview(%{dir: dir}, name: name, build?: true) do
        {:ok, report} -> {:ok, %{output: render_preview(report, proposal), is_error: false}}
        {:error, reason} -> error("preview refused: " <> describe(reason))
      end
    else
      {:refused, result} -> {:ok, result}
    end
  end

  # ── forge ──────────────────────────────────────────────────────────────────────────

  defp forge(params, context, principal) do
    with {:ok, name} <- name(params),
         {:ok, dir} <- directory(params, context),
         {:ok, proposal} <- proposal(dir, name, params),
         # Last, and after everything that could be answered without spending a build: the
         # entry exists before the effect does, and a ledger that cannot record refuses.
         {:ok, effect_id} <- open(:forge, %{module: @prefix <> name}, principal, context) do
      opts =
        [author: principal, name: name, timeout_ms: build_timeout()]
        |> put_present(:eval, proposal.eval)
        |> put_present(:start_config, proposal.start_config)

      settling(effect_id, :forge, fn ->
        case forge_module().forge(%{dir: dir}, opts) do
          {:ok, forged} ->
            settle(effect_id, %{status: :ok, result: forged_result(forged)})
            {:ok, %{output: render_forged(forged), is_error: false}}

          {:error, reason} ->
            settle(effect_id, %{status: :failed, error: {:forge_refused, class(reason)}})
            error("forge refused: " <> describe(reason))
        end
      end)
    else
      {:refused, result} -> {:ok, result}
    end
  end

  # The fields `Effects.Runner` settles a `:forge` with, from the forge's own receipt. The
  # ledger keeps exactly these (`@result_fields`); anything else here would be dropped.
  # `nodes` is where the bundle now is, which for a local forge is this node.
  defp forged_result(forged) do
    %{
      artifact_id: Map.get(forged, :artifact_id),
      module: Map.get(forged, :module),
      epoch: Map.get(forged, :epoch),
      signer: Map.get(forged, :signer),
      source_sha256: Map.get(forged, :source_sha256),
      nodes: [node()]
    }
  end

  # ── deploy ─────────────────────────────────────────────────────────────────────────

  defp deploy(params, context, principal) do
    with {:ok, artifact} <- forged_artifact(string(params, :artifact_id)),
         :ok <- deployable_kind?(artifact),
         :ok <- agreed_deploy_name(artifact, context),
         :ok <- authored_by?(artifact, principal),
         {:ok, effect_id} <- open(:deploy, %{nodes: [node()]}, principal, context) do
      settling(effect_id, :deploy, fn ->
        case forge_module().deploy(artifact, [node()]) do
          {:ok, outcome} ->
            settle(effect_id, %{status: :ok, result: deployed_result(artifact, outcome)})
            {:ok, %{output: render_deployed(artifact, outcome), is_error: false}}

          {:error, reason} ->
            settle(effect_id, %{status: :failed, error: {:deploy_refused, class(reason)}})
            error("deploy refused: " <> describe(reason))
        end
      end)
    else
      {:refused, result} -> {:ok, result}
    end
  end

  # A lane-W bundle carries its kind in the manifest the signature covers, and this tool
  # deploys exactly one of them. A `:policy` component is the *permission engine*: deploying
  # one is deciding what this node's rules are, which is the operator's verb
  # (`capabilities.admit`, `wasm.deploy`) and not a session's — `Ouroboros.Wasm.Forge.forge/2`
  # already refuses to build anything but a capability, and this is the same judgement on the
  # other side of the seam, where the bytes come off a disk rather than out of a build.
  defp deployable_kind?(%Artifact{kind: :capability}), do: :ok

  defp deployable_kind?(%Artifact{kind: kind}),
    do:
      refuse(
        "that bundle is a #{inspect(kind)} component, and this tool deploys capabilities. " <>
          "A policy component decides what this node's permission rules are, which is an " <>
          "operator's verb. Nothing was deployed."
      )

  # What the permission engine was actually shown (Q-B). `Tools.classify/3` resolves the
  # artifact id against the ring, verifies the manifest and puts the *resolved name* in the
  # request context; the loop hands that name back on the tool context as
  # `forge_evaluated_name`. So `Forge(vet)` allowing a deploy is a sentence about deploying
  # `vet`, and a
  # bundle swapped at that id between the decision and this moment is refused by name rather
  # than shipped under somebody else's allow.
  #
  # Absent — a caller that did not come through the loop's classification — constrains
  # nothing here, and the fresh decode, the manifest verification, the kind and the author
  # all still stand. This is the one check that has an answer only because the engine was
  # asked, so it is the one check that can be missing.
  defp agreed_deploy_name(%Artifact{name: name}, context) do
    case Map.get(context, :forge_evaluated_name) do
      nil ->
        :ok

      ^name ->
        :ok

      other ->
        refuse(
          "the permission decision for this call was about #{inspect(other)} and that " <>
            "artifact id now resolves to #{inspect(name)}. One decision, one bundle. " <>
            "Nothing was deployed."
        )
    end
  end

  # A session deploys what it forged. The author is inside the signed manifest — it is what
  # `Wasm.Forge` put there from `context.principal` — so this compares the signature's own
  # claim about provenance against the session asking, and never two strings the same
  # session supplied.
  defp authored_by?(%Artifact{metadata: metadata}, principal) do
    if Map.get(metadata, :author) == principal do
      :ok
    else
      refuse(
        "that bundle was forged by another principal. A session deploys what it forged; " <>
          "the operator's own verbs deploy anything else. Nothing was deployed."
      )
    end
  end

  defp deployed_result(artifact, outcome) do
    %{
      artifact_id: artifact.id,
      module: @prefix <> artifact.name,
      epoch: artifact.epoch,
      nodes: [node()],
      state: Map.get(outcome, :state)
    }
  end

  # ── status ─────────────────────────────────────────────────────────────────────────

  defp status(_params, _context, principal) do
    {:ok, %{output: render_status(ring(principal)), is_error: false}}
  end

  # ── the forged ring ────────────────────────────────────────────────────────────────

  # `<data_dir>/wasm/forged/`, the directory `Ouroboros.Wasm.Forge` retains a bundle in and
  # reads it back from. Derived the same way it derives it, because a second spelling of one
  # directory is a deploy that reads somewhere the forge did not write.
  defp forged_root do
    case Application.get_env(:ouroboros, :data_dir) do
      dir when is_binary(dir) and dir != "" -> {:ok, Path.join([dir, "wasm", "forged"])}
      _unset -> {:error, :no_data_dir}
    end
  end

  defp forged_artifact(artifact_id) do
    with :ok <- artifact_id?(artifact_id) do
      case resolve_bundle(artifact_id) do
        {:ok, artifact} -> {:ok, artifact}
        {:error, reason} -> refuse(unresolvable(reason))
      end
    end
  end

  # The bundle an artifact id names, as it is on disk *at this instant*: read, decoded, and
  # its manifest verified against this node's own trust policy the way
  # `Ouroboros.Wasm.PolicyEngine` verifies one before loading a byte. `request_context/1` and
  # `deploy/3` both call it, and both call it fresh — a bundle judged at classification and
  # deployed out of a variable would be a bundle nothing re-read after the decision.
  #
  # The verification is not ceremony. What `deploy/3` reads off this artifact — its author,
  # its kind, its name — is only worth reading if the signature covers it, and every one of
  # those three is a gate. Unverified they are three strings out of a file in a directory a
  # sandboxed shell could have written.
  defp resolve_bundle(artifact_id) do
    with {:ok, root} <- forged_root(),
         {:ok, bundle} <- bundle_bytes(Path.join(root, artifact_id <> Bundle.extension())),
         {:ok, artifact} <- decoded(bundle) do
      case Verifier.verify_manifest(artifact, trust_policy()) do
        :ok -> {:ok, artifact}
        {:error, reason} -> {:error, {:unverifiable, reason}}
      end
    end
  end

  defp bundle_bytes(path) do
    case read_bundle(path) do
      {:ok, bundle} -> {:ok, bundle}
      _unreadable -> {:error, :no_such_bundle}
    end
  end

  defp decoded(bundle) do
    case Bundle.decode(bundle) do
      {:ok, %{artifact: %Artifact{} = artifact}} -> {:ok, artifact}
      _undecodable -> {:error, :undecodable_bundle}
    end
  end

  # This node's own trust policy, read here rather than taken from anywhere a caller could
  # name it: which signers this node trusts is an operator's fact about this machine.
  defp trust_policy, do: Application.get_env(:ouroboros, :upgrade_trust_policy, [])

  # Three different things to tell somebody, kept apart: the id names nothing, the file is
  # not a bundle, or the bundle is one this node will not act on.
  defp unresolvable(:no_such_bundle),
    do:
      "no bundle this node forged is filed under that artifact id. Call forge with " <>
        "operation=status to see the ones there are; the ring keeps the last #{@max_listed}."

  defp unresolvable(:undecodable_bundle),
    do:
      "the file filed under that artifact id is not a bundle this node can decode. " <>
        "Nothing was deployed."

  defp unresolvable({:unverifiable, reason}),
    do:
      "that bundle's signed manifest does not verify against this node's trust policy " <>
        "(#{describe(reason)}). A bundle whose signature this node cannot check is not one " <>
        "it will run, whoever forged it. Nothing was deployed."

  defp unresolvable(reason), do: describe(reason)

  # The one place a string the model wrote becomes part of a filename, so it is held to the
  # charset `Wasm.Forge` files a bundle under before `Path.join/2` is asked anything.
  defp artifact_id?(id) do
    if is_binary(id) and Regex.match?(@artifact_id, id),
      do: :ok,
      else:
        refuse(
          "that is not an artifact id. An id is what a forge answered with: letters, " <>
            "digits, `-` and `_`."
        )
  end

  defp read_bundle(path) do
    with {:ok, %File.Stat{type: :regular, size: size}} <- File.lstat(path),
         true <- size <= Bundle.max_bytes() do
      File.read(path)
    else
      _unreadable -> :error
    end
  end

  # Every bundle in the ring this principal authored, newest first, with the register's own
  # answer about each. Reads each bundle whole because that is what decoding one takes; the
  # ring is bounded at #{@max_listed}, which is what bounds this.
  defp ring(principal) do
    with {:ok, root} <- forged_root(),
         {:ok, entries} <- File.ls(root) do
      entries
      |> Enum.filter(&String.ends_with?(&1, Bundle.extension()))
      |> Enum.map(&{&1, mtime(Path.join(root, &1))})
      |> Enum.sort_by(&elem(&1, 1), :desc)
      |> Enum.take(@max_listed)
      |> Enum.flat_map(fn {entry, _mtime} -> mine(Path.join(root, entry), principal) end)
    else
      _unreadable -> []
    end
  end

  defp mine(path, principal) do
    with {:ok, bundle} <- read_bundle(path),
         {:ok, %{artifact: %Artifact{metadata: %{author: ^principal}} = artifact}} <-
           Bundle.decode(bundle) do
      [%{artifact: artifact, state: register_state(artifact.id)}]
    else
      _theirs_or_unreadable -> []
    end
  end

  defp mtime(path) do
    case File.stat(path, time: :posix) do
      {:ok, %File.Stat{mtime: mtime}} -> mtime
      {:error, _absent} -> 0
    end
  end

  # What this node's rollout register says about the bundle, which is the only thing that
  # says whether it is live. Total, and `:unknown` when the register cannot answer: a
  # register that is down has not told us anything is deployed.
  defp register_state(artifact_id) do
    case Registry.get(artifact_id) do
      {:ok, entry} -> entry
      :not_found -> nil
    end
  rescue
    _error -> nil
  catch
    _kind, _reason -> nil
  end

  # ── the project ────────────────────────────────────────────────────────────────────

  defp name(params) do
    case param(params, :name) do
      name when is_binary(name) and name != "" ->
        if Artifact.name?(name),
          do: {:ok, name},
          else:
            refuse(
              "#{inspect(name)} is not a capability name. A name is lowercase letters, " <>
                "digits, `.`, `-` and `_`, starts with a letter or a digit, and is at " <>
                "most 64 bytes — and it is compared exactly, so leading or trailing " <>
                "whitespace is part of it."
            )

      _absent ->
        refuse("`name` is required: it is what the capability will be called.")
    end
  end

  # The same containment `read` uses, with the session's own scope, before `Wasm.Forge` is
  # told a directory exists. A path outside the workspace never reaches the forge, so
  # nothing outside it is walked, read, or hashed.
  defp directory(params, context) do
    case {Map.get(context, :scope), string(params, :path)} do
      {scope, path} when is_map(scope) and is_binary(path) ->
        contained(path, scope)

      {scope, _no_path} when is_map(scope) ->
        refuse("`path` is required: the directory holding the capability's Cargo project.")

      _no_scope ->
        refuse("this call carries no workspace, so there is no directory it could reach.")
    end
  end

  defp contained(path, scope) do
    case Paths.resolve(path, scope) do
      {:ok, resolved} ->
        if File.dir?(resolved),
          do: {:ok, resolved},
          else: refuse("`path` must name a directory holding the capability's Cargo project.")

      {:error, reason} ->
        refuse("that path is not usable: #{Paths.describe_error(reason)}")
    end
  end

  # The proposal the forge will be given: this project's `manifest.json` where it has one,
  # with the parameters winning over it. One format serves the operator's
  # `capabilities.admit` and this tool, and it is validated by the same functions
  # (`Ouroboros.Runtime.Capabilities`) rather than by a second, weaker reading of it here.
  defp proposal(dir, name, params) do
    with {:ok, manifest} <- read_proposal(dir),
         :ok <- agreed_name(manifest, name),
         {:ok, eval} <- eval(params, manifest),
         {:ok, start_config} <- start_config(params, manifest) do
      {:ok, %{manifest: manifest, eval: eval, start_config: start_config}}
    end
  end

  defp read_proposal(dir) do
    path = Path.join(dir, @proposal_file)

    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} when size <= @max_manifest_bytes ->
        decode_proposal(path)

      {:ok, %File.Stat{type: :regular, size: size}} ->
        refuse("#{@proposal_file} is #{size} bytes; the bound is #{@max_manifest_bytes}.")

      {:ok, %File.Stat{type: type}} ->
        refuse("#{@proposal_file} is a #{type}, and only a regular file is read.")

      {:error, _absent} ->
        {:ok, nil}
    end
  end

  defp decode_proposal(path) do
    with {:ok, contents} <- File.read(path),
         {:ok, decoded} when is_map(decoded) <- JSON.decode(contents),
         {:ok, manifest} <- Capabilities.wasm_manifest(decoded) do
      {:ok, manifest}
    else
      {:error, reason} ->
        refuse("#{@proposal_file} was refused: #{describe(reason)}")

      _not_an_object ->
        refuse("#{@proposal_file} must be a JSON object.")
    end
  end

  # Two names for one capability is a disagreement, and it is answered before a build rather
  # than after one — the same judgement `Wasm.Forge` makes about the Cargo package name, and
  # for the same reason: a name is not a build product.
  defp agreed_name(nil, _name), do: :ok
  defp agreed_name(%{name: name}, name), do: :ok

  defp agreed_name(%{name: declared}, name),
    do:
      refuse(
        "#{@proposal_file} names #{inspect(declared)} and this call names #{inspect(name)}. " <>
          "One capability, one name."
      )

  defp eval(params, manifest) do
    case param(params, :eval) do
      nil ->
        {:ok, manifest && manifest.eval}

      spec ->
        case Capabilities.wasm_eval(spec) do
          {:ok, validated} -> {:ok, validated}
          {:error, reason} -> refuse("`eval` was refused: #{describe(reason)}")
        end
    end
  end

  defp start_config(params, manifest) do
    case string(params, :start_config) do
      config when is_binary(config) and config != "" ->
        case Capabilities.wasm_start_config(config) do
          {:ok, validated} -> {:ok, validated}
          {:error, reason} -> refuse("`start_config` was refused: #{describe(reason)}")
        end

      _absent ->
        {:ok, manifest && manifest.start && manifest.start.config}
    end
  end

  # ── the ledger ─────────────────────────────────────────────────────────────────────

  # `Effects.Runner`'s shape: the entry exists before the effect, and the failure to write
  # one is the failure of the operation. `authority` is a class and not a rule id — see the
  # moduledoc — and `cause` names the `:tool_call` entry this ran inside, which is the entry
  # that does carry the permission decision.
  defp open(effect, attempt, principal, context) do
    attrs = %{
      id: effect_id(effect),
      effect: effect,
      principal: principal,
      attempt: attempt,
      authority: %{decision: :granted, reason: :native_tool_call},
      cause: cause(effect, context)
    }

    case safe_ledger(fn -> EffectLedger.record_started(attrs, ledger()) end) do
      {:ok, _entry, _disposition} ->
        {:ok, attrs.id}

      other ->
        refuse(
          "Refused: the effect ledger could not record this #{effect} before it ran, so it " <>
            "did not run. A capability nobody can account for afterwards is what that " <>
            "ledger exists to prevent. Ask the operator to check the runtime's effect " <>
            "ledger (#{inspect(other, limit: 5)})."
        )
    end
  end

  # `Effects.Runner`'s discipline for a body that can stop being anybody's to settle
  # (`runner.ex:164`). Three ways an entry written `:started` never reaches a `settle`, and
  # each is closed by a different mechanism:
  #
  #   * the body **raises** or **throws**. The entry is settled `:failed` with the class and
  #     the reason is re-raised unchanged, so `run/2`'s own handler renders it to the model.
  #     A `rescue` that swallowed it would turn a build that crashed into a quiet refusal.
  #   * the task is **brutally killed** — `Tools.execute/4` does exactly that at the loop's
  #     tool timeout — and no line in this process runs at all. That is what `watch_runner/3`
  #     is for: the ledger monitors this process before the effect starts, and a monitor that
  #     fires on a `:started` entry settles it `:ambiguous`, which is the honest word for
  #     "a build may have happened and nobody knows".
  #   * it returns, and both branches inside settle it themselves.
  #
  # A `watch_runner/3` that fails is **not** a refusal, unlike in `Effects.Runner`. There the
  # watch is attached before the effect is permitted to start, so refusing costs nothing; here
  # the entry is already durable and the operation is already accounted for, and stopping a
  # forge the ledger *did* record because a monitor could not be attached would trade the
  # capability for bookkeeping. What is lost is the ambiguity settlement on a kill, and the
  # entry stays `:started` — which is exactly what it meant before this existed.
  defp settling(effect_id, effect, fun) do
    watch(effect_id)
    fun.()
  rescue
    error ->
      settle(effect_id, %{status: :failed, error: crashed(effect, :error)})
      reraise error, __STACKTRACE__
  catch
    kind, reason ->
      settle(effect_id, %{status: :failed, error: crashed(effect, kind)})
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  defp crashed(:forge, kind), do: {:forge_crashed, kind}
  defp crashed(:deploy, kind), do: {:deploy_crashed, kind}

  defp watch(effect_id) do
    case safe_ledger(fn -> EffectLedger.watch_runner(effect_id, self(), ledger()) end) do
      :ok ->
        :ok

      other ->
        Logger.warning(
          "the effect ledger could not watch this forge's runner (#{inspect(other, limit: 5)}); " <>
            "#{effect_id} will stay :started rather than settling :ambiguous if this call " <>
            "is killed where it stands"
        )

        :ok
    end
  end

  defp settle(effect_id, outcome) do
    _ = safe_ledger(fn -> EffectLedger.settle(effect_id, outcome, ledger()) end)
    :ok
  end

  defp effect_id(effect) do
    digest =
      :sha256
      |> :crypto.hash(
        :erlang.term_to_binary(
          {node(), effect, System.system_time(:nanosecond),
           System.unique_integer([:positive, :monotonic])}
        )
      )
      |> Base.encode16(case: :lower)

    "#{effect}-" <> binary_slice(digest, 0, 32)
  end

  # The `:tool_call` ledger entry for the call this is happening inside. That entry exists
  # whether or not this node's audit stream is on — the loop writes it on every admitted tool
  # call — so the chain to the permission decision must not depend on audit either (Q-A). The
  # loop puts its id on the tool context as `ledger_effect_id`, plainly, beside `principal`.
  #
  # Two hops, and this is the first: `cause.signal_id` names the `:tool_call` entry, and that
  # entry's own `attempt.permission_entry_id` names the `:permission` entry that holds the
  # decision. Each hop written by the thing that knew the fact.
  defp cause(effect, context) do
    base = %{signal_type: "native.tool.forge.#{effect}"}

    case ledger_effect_id(context) do
      id when is_binary(id) and id != "" -> Map.put(base, :signal_id, id)
      _absent -> base
    end
  end

  # Never by `rescue`: a context with no key, and one whose `:audit` is `nil` or is not a map,
  # are absence, and each is written down as such rather than raised and caught. The audit
  # fields stay as a fallback for a caller that assembles the context the way the loop did
  # before this key existed. The guard is the only shape check that is left — a non-map
  # context has already failed `principal/1` two calls earlier, which is where it belongs.
  defp ledger_effect_id(context) when is_map(context) do
    case Map.get(context, :ledger_effect_id) do
      id when is_binary(id) and id != "" -> id
      _absent -> audit_effect_id(Map.get(context, :audit))
    end
  end

  defp audit_effect_id(%{fields: fields}) when is_map(fields),
    do: Map.get(fields, "ledger_effect_id")

  defp audit_effect_id(_absent), do: nil

  defp safe_ledger(fun) do
    fun.()
  rescue
    error -> {:error, {:effect_ledger_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:effect_ledger_failure, kind, inspect(reason)}}
  end

  # ── rendering ──────────────────────────────────────────────────────────────────────

  defp render_preview(report, proposal) do
    Enum.join(
      [
        "#{Map.get(report, :name)} #{Map.get(report, :version)} would be accepted as a " <>
          "capability project.",
        "  files: #{Enum.join(Map.get(report, :files, []), ", ")}",
        "  bytes: #{Map.get(report, :bytes)}   source sha256: #{Map.get(report, :source_sha256)}",
        "  lock: #{inspect(Map.get(report, :lock))}   placement: #{inspect(Map.get(report, :placement))}",
        "  toolchain: #{render_toolchain(Map.get(report, :toolchain))}",
        "  dry build: #{render_build(Map.get(report, :build))}",
        "  " <> render_proposal(proposal),
        "Nothing was signed, no epoch was allocated and no bundle was written: a preview " <>
          "that built is not a prepared deploy. Call forge next."
      ],
      "\n"
    )
  end

  defp render_toolchain(toolchain) when is_map(toolchain) do
    "cargo #{inspect(Map.get(toolchain, :cargo))}, target #{Map.get(toolchain, :target)} " <>
      "installed=#{Map.get(toolchain, :target_installed?)}, cache #{inspect(Map.get(toolchain, :cache))}, " <>
      "sandbox #{Map.get(toolchain, :sandbox)}"
  end

  defp render_toolchain(other), do: inspect(other, limit: 5)

  # `Ouroboros.Wasm.Forge.preview/2` reports a dry build as a map carrying its own
  # `:outcome`, and both outcomes are `{:ok, _}` from the caller's side — the preview
  # *succeeded* in answering. So the outcome is read rather than the shape: a report whose
  # `outcome` this module does not recognise is rendered as itself rather than as either
  # word, because "the build succeeded" is the one sentence here that must never be a guess.
  defp render_build(:skipped), do: "skipped"
  defp render_build(:not_placed_here), do: "not run: a forge of this input would not run here"

  defp render_build(%{outcome: :ok} = report),
    do:
      "succeeded in #{Map.get(report, :ms)} ms; #{Map.get(report, :size)} bytes, " <>
        "sha256 #{Map.get(report, :component_sha256)}"

  # The compiler's own words, in its own field and bounded here rather than trusted to be
  # short: this is the whole of what a model is told about why a build did not happen, and a
  # refusal whose remedy was elided is a refusal with its answer cut off.
  defp render_build(%{outcome: :failed} = report) do
    "FAILED after #{Map.get(report, :ms)} ms: #{Map.get(report, :reason)}" <>
      build_output(Map.get(report, :output))
  end

  defp render_build({:error, reason}), do: "FAILED: " <> describe(reason)
  defp render_build(other), do: inspect(other, limit: 10, printable_limit: 2_048)

  defp build_output(output) when is_binary(output) and output != "", do: "\n  " <> clip(output)
  defp build_output(_none), do: ""

  defp clip(text) when byte_size(text) <= @max_build_output_bytes, do: text

  defp clip(text) do
    valid_prefix(binary_part(text, 0, @max_build_output_bytes)) <>
      "\n  … truncated at #{@max_build_output_bytes} bytes."
  end

  # The cut is by bytes and walked back to a whole character: a string half a codepoint long
  # is one no surface downstream can encode. The same walk `Tools.Capability` does.
  defp valid_prefix(binary) do
    cond do
      String.valid?(binary) -> binary
      byte_size(binary) == 0 -> binary
      true -> binary |> binary_part(0, byte_size(binary) - 1) |> valid_prefix()
    end
  end

  defp render_proposal(%{eval: nil}),
    do:
      "no evaluation spec: this node's signer requires one by default " <>
        "(`signing_require_wasm_eval`), so a forge without it will be refused. Put an " <>
        "`eval` block in #{@proposal_file}, or pass one."

  defp render_proposal(%{eval: eval}),
    do:
      "evaluation spec: #{length(Map.get(eval, :probes, []))} probe(s), " <>
        "budget #{Map.get(eval, :budget_ms)} ms, required #{inspect(Map.get(eval, :required))}"

  defp render_forged(forged) do
    Enum.join(
      [
        "Forged and signed #{Map.get(forged, :name)}.",
        "  artifact id: #{Map.get(forged, :artifact_id)}",
        "  module: #{Map.get(forged, :module)}   epoch: #{Map.get(forged, :epoch)}",
        "  component sha256: #{Map.get(forged, :component_sha256)}   size: #{Map.get(forged, :size)}",
        "  world: #{Map.get(forged, :world)}   imports: #{inspect(Map.get(forged, :imports))}",
        "  signer: #{Map.get(forged, :signer)}   source sha256: #{Map.get(forged, :source_sha256)}",
        "The bundle is on this node and nothing is running it. Call forge with " <>
          "operation=deploy and artifact_id=#{Map.get(forged, :artifact_id)} to make it live."
      ],
      "\n"
    )
  end

  defp render_deployed(artifact, outcome) do
    entry = register_state(artifact.id)

    Enum.join(
      [
        "#{artifact.name} is #{inspect(Map.get(outcome, :state))} on #{node()}.",
        "  module: #{@prefix <> artifact.name}   epoch: #{artifact.epoch}",
        "  component sha256: #{artifact.component_sha256}",
        "  " <> render_eval_report(entry)
      ],
      "\n"
    )
  end

  # The register's own record of what the rollout's evaluation found, bounded: it is a
  # report about probes this node ran, and a capability's evaluation can name as much of its
  # own answers as the register's 32 KiB allows.
  defp render_eval_report(%{eval_report: report}) when is_map(report),
    do: "evaluation: " <> inspect(report, limit: 20, printable_limit: 1_024)

  defp render_eval_report(_entry), do: "evaluation: none recorded for this rollout."

  defp render_status([]) do
    "This session has forged nothing on this node. Call forge with operation=preview to " <>
      "check a project, then operation=forge to build and sign it."
  end

  defp render_status(entries) do
    header =
      "#{length(entries)} bundle(s) this session forged and this node still holds, newest " <>
        "first. The ring keeps the last #{@max_listed} of anybody's."

    Enum.join([header | Enum.map(entries, &render_ring_entry/1)], "\n")
  end

  defp render_ring_entry(%{artifact: artifact, state: entry}) do
    "  #{artifact.name}  artifact #{artifact.id}  epoch #{artifact.epoch}  " <>
      "sha256 #{artifact.component_sha256}  register #{register_label(entry)}"
  end

  defp register_label(%{state: state}), do: inspect(state)
  defp register_label(_absent), do: "not deployed"

  # ── refusals ───────────────────────────────────────────────────────────────────────

  # The forge's vocabulary, by class, in this runtime's own voice. Every reason it mints is
  # a tagged tuple; the ones a model can act on are named, and everything else is rendered
  # bounded rather than echoed at whatever length it arrived.
  defp describe({:name_mismatch, asked, declared}),
    do:
      "the project's Cargo package is #{inspect(declared)} and this call named " <>
        "#{inspect(asked)}. The package name is the capability's name."

  defp describe({:file_not_allowed, path}),
    do:
      "#{inspect(path)} is not a file a capability project may contain. The list is " <>
        "Cargo.toml, Cargo.lock, README.md, #{@proposal_file} and src/**.rs — nothing else, " <>
        "and no build.rs."

  defp describe({:missing_files, missing}),
    do: "the project is missing #{inspect(missing)}."

  defp describe({:too_many_files, found, bound}),
    do: "the project has #{found} files; the bound is #{bound}."

  defp describe({:input_too_large, total, bound}),
    do: "the project is #{total} bytes; the bound is #{bound}."

  defp describe({:symlink_refused, path}),
    do: "#{inspect(path)} is a symlink. A forge follows none: it reads what it can see."

  defp describe({:build_script_refused, path}),
    do: "#{inspect(path)} is a build script. A build script is code that runs at build time."

  defp describe({:lock_not_the_sdk_lock, reason}),
    do:
      "Cargo.lock is not the guest SDK's lock (#{inspect(reason, limit: 5)}). Copy " <>
        "tui/wasm/guest/Cargo.lock and add only this project's own [[package]] entry."

  defp describe({:invalid_guest_dependency, reason}),
    do:
      "the ouroboros-guest dependency is not one this node accepts " <>
        "(#{inspect(reason, limit: 5)}). It is a path dependency on this checkout's " <>
        "tui/wasm/guest and nothing else."

  defp describe({:profile_override_refused, key}),
    do:
      "[profile.release] may not change #{inspect(key)}: it is what keeps the import list at `log`."

  defp describe({:build_failed, reason}),
    do: "cargo did not produce a component: #{inspect(reason, limit: 10, printable_limit: 2_048)}"

  defp describe({:sandbox_unavailable, reason}),
    do:
      "this node has no OS sandbox to build inside (#{inspect(reason, limit: 5)}), and a " <>
        "forge does not build without one."

  defp describe({:forge_refused, _reason, why}) when is_binary(why), do: why

  defp describe({:forge_timeout, ms}),
    do: "the build passed its #{ms} ms ceiling and was stopped."

  defp describe({:no_guest_sdk, path}),
    do: "this node has no guest SDK checkout at #{inspect(path)} to build against."

  defp describe(:no_data_dir),
    do: "this node has no data directory, so there is nowhere to keep a forged bundle."

  defp describe({:invalid_author, _author}),
    do: "the author this forge would have been signed under is not a usable principal."

  defp describe(reason), do: inspect(reason, limit: 8, printable_limit: 512)

  # What the ledger keeps of a failure: the shape, never the text. `sanitize_error/1` would
  # reduce a string to `:text` anyway; this makes what is recorded legible instead.
  defp class(reason) when is_tuple(reason) and tuple_size(reason) > 0, do: elem(reason, 0)
  defp class(reason) when is_atom(reason), do: reason
  defp class(_reason), do: :refused

  # ── seams and helpers ──────────────────────────────────────────────────────────────

  # See the moduledoc. Node configuration, an operator's key, and the only way a test can
  # prove the forge was never reached rather than that it refused.
  defp forge_module, do: Application.get_env(:ouroboros, :forge_module, Ouroboros.Wasm.Forge)

  defp ledger, do: Application.get_env(:ouroboros, :forge_tool_ledger, EffectLedger)

  defp build_timeout, do: Ouroboros.Wasm.Forge.build_timeout([])

  # A parameter under either spelling, **string key first** (LOW-6). The loop hands this
  # module atom keys (`Tools.atomize/2` converted the declared ones and dropped everything
  # else); a caller reaching the action directly may not have; and the classifier, which
  # reads the model's JSON, only ever sees strings.
  #
  # The order is the point. `Ouroboros.Provider.Native.Tools.classify/3` calls this same
  # function through `request_context/1`, so a map carrying *both* spellings of a key is
  # judged and executed on the same value — where the two used to disagree, a call could be
  # classified as one operation and run as another. String first because that is the spelling
  # the classifier is guaranteed to see; an atom key holding the schema's own `nil` default is
  # absence, not a value, so it falls through rather than shadowing.
  defp param(params, key) do
    case Map.fetch(params, Atom.to_string(key)) do
      {:ok, nil} -> atom_param(params, key)
      {:ok, value} -> value
      :error -> atom_param(params, key)
    end
  end

  defp atom_param(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} -> value
      :error -> nil
    end
  end

  # A string parameter, or `nil`. The empty string is absence: it is the schema's default for
  # every one of them, and it is not a name, a path or an artifact id under any reading — so
  # this is a statement about *whether* a parameter was given and never a normalisation of
  # what it says. Nothing here trims (F1).
  defp string(params, key) do
    case param(params, key) do
      "" -> nil
      value when is_binary(value) -> value
      _other -> nil
    end
  end

  defp put_present(opts, _key, nil), do: opts
  defp put_present(opts, key, value), do: Keyword.put(opts, key, value)

  defp error(message), do: {:ok, %{output: message, is_error: true}}

  # Tagged rather than shaped like a result, for `Tools.Capability`'s reason: a tool result
  # is itself `{:ok, %{is_error: true}}`, and a `with` that could not tell the two apart
  # would read every refusal above as a successful forge.
  defp refuse(message), do: {:refused, %{output: message, is_error: true}}
end
