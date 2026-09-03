defmodule Ouroboros.Runtime.Capabilities do
  @moduledoc """
  Operator admission for workspace-authored capability proposals, in either lane.

  The selected model writes a proposal under `.ouroboros/capabilities/<Name>/`. This module
  is the operator surface that reads those files inside an admitted workspace, previews them
  without loading or deploying anything, and admits them through the forge and rollout lane
  the proposal belongs to. Gateway `:operate` is the authority; `Control.Grants` are not
  consulted — those grants are for mesh agent effect signals.

  ## Two lanes, told apart by one file

  A proposal directory holding a `Cargo.toml` is a **lane W** proposal: a Cargo project on
  the guest SDK, previewed and admitted through `Ouroboros.Wasm.Forge` (docs/WASM.md §7.7).
  Anything else is the **lane B** proposal this module has always taken: `source.ex`, an
  optional `test.exs`, and a module name under `Ouroboros.Capability.`.

  It is one file and not a manifest field on purpose. A `"lane": "wasm"` key would be a
  claim the directory could contradict — a Cargo project labelled BEAM, or the reverse — and
  the thing that actually decides how these bytes are built is whether cargo has a manifest
  to read. The `manifest.json` beside it still carries what the operator has to state
  either way: the name, a description, the evaluation spec the signature will cover, and
  whether to start it.

  A lane-W `manifest.json` names the capability, and the name must be the one the Cargo
  manifest gives the package. Two names for one thing is how a proposal comes to be
  described as one capability and deployed as another, so a disagreement is a refusal
  rather than a preference for one of them.
  """

  alias Ouroboros.Mesh
  alias Ouroboros.Runtime.Manifesto
  alias Ouroboros.Upgrade.Forge
  alias Ouroboros.Upgrade.Forge.Source
  alias Ouroboros.Upgrade.Rollout
  alias Ouroboros.Upgrade.Rollout.Evaluation
  alias Ouroboros.Wasm
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @capability_name ~r/^Ouroboros\.Capability\.[A-Z][A-Za-z0-9_]*(\.[A-Z][A-Za-z0-9_]*)*$/
  @max_capability_segments 8
  @manifest_keys MapSet.new(["module", "description", "eval", "start"])
  @wasm_manifest_keys MapSet.new(["name", "description", "eval", "start"])
  @start_keys MapSet.new(["id", "role"])
  @wasm_start_keys MapSet.new(["config"])
  @max_start_config_bytes 16 * 1024
  @source_file "source.ex"
  @test_file "test.exs"
  @manifest_file "manifest.json"
  @cargo_file "Cargo.toml"

  @doc "Lists proposals under the workspace proposal root."
  @spec list(String.t()) :: {:ok, [map()]} | {:error, term()}
  def list(workspace) when is_binary(workspace) do
    with {:ok, root} <- canonical_workspace(workspace),
         {:ok, names} <- list_names(root) do
      {:ok, Enum.map(names, &summary(root, &1))}
    end
  end

  def list(_workspace), do: {:error, :invalid_workspace}

  @doc "Compiles and tests one proposal in the build peer. Does not load it here."
  @spec preview(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def preview(workspace, path) when is_binary(workspace) and is_binary(path) do
    with {:ok, proposal} <- read(workspace, path) do
      preview_lane(proposal)
    end
  end

  def preview(_workspace, _path), do: {:error, :invalid_proposal_path}

  defp preview_lane(%{lane: :beam} = proposal) do
    with {:ok, source} <- source_record(proposal, "preview"),
         {:ok, result} <- Forge.preview(source, preview_opts(proposal)) do
      {:ok, preview_result(proposal, result)}
    end
  end

  # C9's validation always; the build only where this node has a toolchain and a warm cache.
  # A preview that could not build says so — it does not report a validated proposal as if it
  # had compiled.
  defp preview_lane(%{lane: :wasm} = proposal) do
    with {:ok, result} <- Wasm.Forge.preview(%{dir: proposal.directory}, name: proposal.name) do
      {:ok,
       %{
         path: proposal.path,
         lane: :wasm,
         module: "wasm/" <> proposal.name,
         name: proposal.name,
         description: proposal.description,
         version: result.version,
         files: result.files,
         input_bytes: result.bytes,
         source_sha256: result.source_sha256,
         lock: result.lock,
         toolchain: result.toolchain,
         build: result.build
       }}
    end
  end

  @doc """
  Forges, deploys, and optionally starts one proposal.

  Options: `:author` (recorded in forge provenance; defaults to `"operator"`),
  `:nodes` (defaults to `[node()]`).
  """
  @spec admit(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def admit(workspace, path, opts \\ [])

  def admit(workspace, path, opts)
      when is_binary(workspace) and is_binary(path) and is_list(opts) do
    with {:ok, proposal} <- read(workspace, path) do
      admit_lane(proposal, opts)
    end
  end

  def admit(_workspace, _path, _opts), do: {:error, :invalid_proposal_path}

  # Lane W's admit is the agent surface's forge and deploy with the operator in the
  # principal's place: same module, same C9 validation, same sandbox, same signature, same
  # rollout. What `:operate` buys is the authority to ask for it, and nothing else.
  defp admit_lane(%{lane: :wasm} = proposal, opts) do
    forge_opts =
      [author: author(opts), nodes: nodes(opts), name: proposal.name]
      |> maybe_put(:eval, proposal.eval)
      |> maybe_put(:start_config, proposal_start_config(proposal))

    with {:ok, forged} <- Wasm.Forge.forge(%{dir: proposal.directory}, forge_opts),
         {:ok, outcome} <- Wasm.Forge.deploy(forged.artifact, nodes(opts)) do
      {:ok,
       %{
         path: proposal.path,
         lane: :wasm,
         module: forged.module,
         name: forged.name,
         artifact_id: forged.artifact_id,
         component_sha256: forged.component_sha256,
         epoch: forged.epoch,
         nodes: Map.get(outcome, :nodes, []),
         state: Map.get(outcome, :state),
         started: Map.get(outcome, :started)
       }}
    end
  end

  defp admit_lane(%{lane: :beam} = proposal, opts) do
    with {:ok, source} <- source_record(proposal, author(opts)),
         {:ok, artifact} <- Forge.forge(source, forge_opts(proposal, opts)),
         {:ok, outcome} <-
           Rollout.deploy(artifact, proposal.module, nodes(opts),
             source_sha256: source.sha256,
             eval: proposal.eval
           ) do
      {:ok, admit_result(proposal, outcome, maybe_start(proposal, outcome))}
    end
  end

  defp proposal_start_config(%{start: %{config: config}}), do: config
  defp proposal_start_config(_proposal), do: nil

  defp read(workspace, path) do
    with {:ok, root} <- canonical_workspace(workspace),
         {:ok, relative} <- relative_path(path),
         {:ok, directory} <- contained_directory(root, relative),
         {:ok, manifest} <- read_manifest(directory) do
      if File.regular?(Path.join(directory, @cargo_file)),
        do: read_wasm(directory, relative, manifest),
        else: read_beam(directory, relative, manifest)
    end
  end

  defp read_beam(directory, relative, manifest) do
    with :ok <- ensure_manifest_keys(manifest, @manifest_keys),
         {:ok, source} <- read_required_file(directory, @source_file),
         {:ok, test_source} <- read_optional_file(directory, @test_file),
         {:ok, module} <- capability_module(manifest["module"]),
         {:ok, description} <- required_string(manifest, "description"),
         {:ok, eval} <- optional_eval(manifest),
         {:ok, start} <- optional_start(manifest) do
      {:ok,
       %{
         lane: :beam,
         path: relative,
         directory: directory,
         module: module,
         description: description,
         source: source,
         test_source: test_source,
         eval: eval,
         start: start
       }}
    end
  end

  # Nothing here reads the Cargo project: `Ouroboros.Wasm.Forge` owns C9, and a second,
  # weaker copy of its file allow-list in this module would be a second place for it to be
  # wrong. What is read here is the operator's own manifest beside it.
  defp read_wasm(directory, relative, manifest) do
    with :ok <- ensure_manifest_keys(manifest, @wasm_manifest_keys),
         {:ok, name} <- capability_name(manifest["name"]),
         {:ok, description} <- required_string(manifest, "description"),
         {:ok, eval} <- optional_eval(manifest),
         {:ok, start} <- optional_wasm_start(manifest) do
      {:ok,
       %{
         lane: :wasm,
         path: relative,
         directory: directory,
         name: name,
         description: description,
         eval: eval,
         start: start
       }}
    end
  end

  defp capability_name(name) do
    if Wasm.Artifact.name?(name),
      do: {:ok, name},
      else: {:error, {:invalid_capability_name, inspect(name, limit: 8)}}
  end

  defp optional_wasm_start(manifest) do
    case Map.fetch(manifest, "start") do
      :error ->
        {:ok, nil}

      {:ok, nil} ->
        {:ok, nil}

      {:ok, start} when is_map(start) ->
        unknown = MapSet.difference(MapSet.new(Map.keys(start)), @wasm_start_keys)

        with true <- MapSet.size(unknown) == 0,
             {:ok, config} <- start_config(start) do
          {:ok, %{config: config}}
        else
          false -> {:error, {:unknown_start_keys, Enum.sort(unknown)}}
          {:error, reason} -> {:error, reason}
        end

      {:ok, _other} ->
        {:error, :invalid_start}
    end
  end

  # The `start` id is derived from the name by the signing policy and by
  # `Wasm.Rollout.start_block/1`, so a proposal states only the config — bounded here at the
  # same 16 KiB the signed manifest bounds it at, rather than at the deploy that would refuse
  # it after a build.
  defp start_config(start) do
    case Map.get(start, "config") do
      config when is_binary(config) and byte_size(config) <= @max_start_config_bytes ->
        {:ok, config}

      _other ->
        {:error, {:invalid_manifest_field, "start.config"}}
    end
  end

  defp summary(root, name) do
    relative = Path.join(Manifesto.proposal_root(), name)

    case read(root, relative) do
      {:ok, proposal} ->
        %{
          path: proposal.path,
          lane: proposal.lane,
          module: identity(proposal),
          description: proposal.description,
          readable?: true
        }

      {:error, reason} ->
        %{
          path: relative,
          lane: nil,
          module: nil,
          description: nil,
          readable?: false,
          error: inspect(reason, limit: 16)
        }
    end
  end

  # What this proposal would be deployed as, in the spelling its own lane uses: a module name
  # for lane B, and the rollout register's `"wasm/<name>"` for lane W.
  defp identity(%{lane: :wasm, name: name}), do: "wasm/" <> name
  defp identity(%{module: module}), do: inspect(module)

  defp list_names(root) do
    glob = Path.join([root, Manifesto.proposal_root(), "*", @manifest_file])

    names =
      glob
      |> Path.wildcard()
      |> Enum.map(&Path.basename(Path.dirname(&1)))
      |> Enum.filter(&(&1 != "*" and &1 != ""))
      |> Enum.sort()

    {:ok, names}
  end

  defp canonical_workspace(workspace) do
    case WorkspacePath.canonicalize(workspace) do
      {:ok, root} -> {:ok, root}
      {:error, reason} -> {:error, {:invalid_workspace, reason}}
    end
  end

  defp relative_path(path) when is_binary(path) and path != "" do
    trimmed = path |> String.replace("\\", "/") |> String.trim() |> String.trim_leading("/")

    cond do
      trimmed == "" ->
        {:error, {:invalid_proposal_path, path}}

      Path.type(path) == :absolute or Path.type(trimmed) == :absolute ->
        {:error, {:source_outside_workspace, path}}

      Enum.any?(Path.split(trimmed), &(&1 in ["..", ""])) ->
        {:error, {:source_outside_workspace, path}}

      true ->
        {:ok, trimmed}
    end
  end

  defp relative_path(path), do: {:error, {:invalid_proposal_path, path}}

  defp contained_directory(root, relative) do
    candidate = Path.join(root, relative)

    with {:ok, directory} <- canonicalize_existing_directory(candidate, relative),
         true <- WorkspacePath.within?(directory, root) do
      {:ok, directory}
    else
      false -> {:error, {:source_outside_workspace, relative}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp canonicalize_existing_directory(candidate, relative) do
    case WorkspacePath.canonicalize(candidate) do
      {:ok, directory} -> {:ok, directory}
      {:error, reason} -> {:error, {:proposal_unreadable, relative, reason}}
    end
  end

  defp read_manifest(directory) do
    file = Path.join(directory, @manifest_file)

    with :ok <- ensure_regular_file(file, @manifest_file),
         {:ok, contents} <- File.read(file),
         {:ok, decoded} <- decode_manifest(contents) do
      {:ok, decoded}
    end
  end

  defp decode_manifest(contents) do
    case JSON.decode(contents) do
      {:ok, decoded} when is_map(decoded) -> {:ok, decoded}
      {:ok, _other} -> {:error, :invalid_manifest}
      {:error, reason} -> {:error, {:invalid_manifest, reason}}
    end
  end

  defp ensure_manifest_keys(manifest, allowed) do
    unknown = MapSet.difference(MapSet.new(Map.keys(manifest)), allowed)

    if MapSet.size(unknown) == 0 do
      :ok
    else
      {:error, {:unknown_manifest_keys, Enum.sort(unknown)}}
    end
  end

  defp read_required_file(directory, name) do
    file = Path.join(directory, name)

    with :ok <- ensure_regular_file(file, name),
         {:ok, contents} <- File.read(file),
         :ok <- ensure_nonempty(contents, name) do
      {:ok, contents}
    else
      {:error, :enoent} -> {:error, {:missing_proposal_file, name}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp read_optional_file(directory, name) do
    file = Path.join(directory, name)

    case File.lstat(file) do
      {:error, :enoent} ->
        {:ok, nil}

      {:ok, %File.Stat{type: :regular}} ->
        case File.read(file) do
          {:ok, contents} -> {:ok, contents}
          {:error, reason} -> {:error, {:proposal_unreadable, name, reason}}
        end

      {:ok, %File.Stat{type: type}} ->
        {:error, {:invalid_source_file, name, type}}

      {:error, reason} ->
        {:error, {:proposal_unreadable, name, reason}}
    end
  end

  defp ensure_regular_file(file, name) do
    case File.lstat(file) do
      {:ok, %File.Stat{type: :regular}} -> :ok
      {:ok, %File.Stat{type: type}} -> {:error, {:invalid_source_file, name, type}}
      {:error, :enoent} -> {:error, {:missing_proposal_file, name}}
      {:error, reason} -> {:error, {:proposal_unreadable, name, reason}}
    end
  end

  defp ensure_nonempty("", name), do: {:error, {:empty_source, name}}
  defp ensure_nonempty(_contents, _name), do: :ok

  defp capability_module(name) when is_binary(name) do
    segments = String.split(name, ".")

    if Regex.match?(@capability_name, name) and length(segments) <= @max_capability_segments do
      {:ok, Module.concat(segments)}
    else
      {:error, {:invalid_capability_module, name}}
    end
  rescue
    error -> {:error, {:invalid_capability_module, name, Exception.message(error)}}
  end

  defp capability_module(other), do: {:error, {:invalid_capability_module, other}}

  defp required_string(manifest, key) do
    case Map.get(manifest, key) do
      value when is_binary(value) ->
        trimmed = String.trim(value)
        if trimmed != "", do: {:ok, trimmed}, else: {:error, {:invalid_manifest_field, key}}

      _other ->
        {:error, {:invalid_manifest_field, key}}
    end
  end

  defp optional_eval(manifest) do
    case Map.fetch(manifest, "eval") do
      :error -> {:ok, nil}
      {:ok, nil} -> {:ok, nil}
      {:ok, spec} -> Evaluation.validate(atomize_eval(spec))
    end
  end

  defp optional_start(manifest) do
    case Map.fetch(manifest, "start") do
      :error ->
        {:ok, nil}

      {:ok, nil} ->
        {:ok, nil}

      {:ok, start} when is_map(start) ->
        unknown = MapSet.difference(MapSet.new(Map.keys(start)), @start_keys)

        with true <- MapSet.size(unknown) == 0,
             {:ok, id} <- required_string(start, "id"),
             {:ok, role} <- optional_role(start) do
          {:ok, %{id: id, role: role}}
        else
          false -> {:error, {:unknown_start_keys, Enum.sort(unknown)}}
          {:error, reason} -> {:error, reason}
        end

      {:ok, _other} ->
        {:error, :invalid_start}
    end
  end

  defp optional_role(start) do
    case Map.get(start, "role") do
      nil ->
        {:ok, nil}

      role when is_binary(role) ->
        trimmed = String.trim(role)

        if trimmed != "",
          do: {:ok, trimmed},
          else: {:error, {:invalid_manifest_field, "start.role"}}

      _other ->
        {:error, {:invalid_manifest_field, "start.role"}}
    end
  end

  # JSON arrives with string keys and JSON-shaped expectations. Evaluation.validate/1
  # wants atom keys and tuple expects. Conversion is explicit and fail-closed: anything
  # we cannot name is left for validate/1 to refuse.
  defp atomize_eval(spec) when is_map(spec) do
    spec
    |> Enum.map(fn
      {"probes", probes} when is_list(probes) -> {:probes, Enum.map(probes, &atomize_probe/1)}
      {"budget_ms", value} -> {:budget_ms, value}
      {"max_latency_ms", value} -> {:max_latency_ms, value}
      {"required", "all"} -> {:required, :all}
      {"required", value} -> {:required, value}
      {"initial_state", value} -> {:initial_state, value}
      {key, value} when is_atom(key) -> {key, value}
      {key, value} -> {key, value}
    end)
    |> Map.new()
  end

  defp atomize_eval(other), do: other

  defp atomize_probe(probe) when is_map(probe) do
    probe
    |> Enum.map(fn
      {"input", value} -> {:input, value}
      {"expect", expect} -> {:expect, atomize_expect(expect)}
      {key, value} when is_atom(key) -> {key, value}
      {key, value} -> {key, value}
    end)
    |> Map.new()
  end

  defp atomize_probe(other), do: other

  defp atomize_expect("any_reply"), do: :any_reply
  defp atomize_expect(["any_reply"]), do: :any_reply
  defp atomize_expect(["equals", value]), do: {:equals, value}
  defp atomize_expect(["contains", value]), do: {:contains, value}

  defp atomize_expect(["state_matches", key, value]) when is_binary(key),
    do: {:state_matches, existing_atom(key), value}

  defp atomize_expect(["state_matches", key, value]) when is_atom(key),
    do: {:state_matches, key, value}

  defp atomize_expect(other), do: other

  defp existing_atom(name) do
    String.to_existing_atom(name)
  rescue
    ArgumentError -> name
  end

  defp source_record(proposal, author) do
    attrs = [
      module: proposal.module,
      source: proposal.source,
      author: author
    ]

    attrs =
      if is_binary(proposal.test_source),
        do: Keyword.put(attrs, :test_source, proposal.test_source),
        else: attrs

    case Source.new(attrs) do
      {:ok, source} -> {:ok, source}
      {:error, reason} -> {:error, {:source_rejected, reason}}
    end
  end

  defp preview_opts(%{eval: nil}), do: []
  defp preview_opts(%{eval: eval}), do: [eval: eval]

  defp forge_opts(proposal, opts) do
    [nodes: nodes(opts)]
    |> maybe_put(:eval, proposal.eval)
  end

  defp maybe_put(keyword, _key, nil), do: keyword
  defp maybe_put(keyword, key, value), do: Keyword.put(keyword, key, value)

  defp author(opts) do
    case Keyword.get(opts, :author) do
      author when is_binary(author) and author != "" -> author
      _other -> "operator"
    end
  end

  defp nodes(opts) do
    case Keyword.get(opts, :nodes) do
      nodes when is_list(nodes) and nodes != [] -> nodes
      _other -> [node()]
    end
  end

  defp preview_result(proposal, result) do
    %{
      path: proposal.path,
      lane: :beam,
      module: inspect(proposal.module),
      description: proposal.description,
      source_sha256: result.source_sha256,
      test_report: Map.get(result, :test_report, %{}),
      loaded?: :code.which(proposal.module) != :non_existing
    }
  end

  defp admit_result(proposal, outcome, started) do
    %{
      path: proposal.path,
      lane: :beam,
      module: inspect(proposal.module),
      artifact_id: outcome.artifact_id,
      epoch: outcome.epoch,
      nodes: outcome.nodes,
      state: outcome.state,
      started: started
    }
  end

  defp maybe_start(%{start: nil}, _outcome), do: nil

  defp maybe_start(%{start: start, module: module}, %{state: :live}) do
    opts =
      [agent: module]
      |> maybe_put(:role, start.role)

    case Mesh.start_agent(start.id, opts) do
      {:ok, pid} -> %{id: start.id, node: node(pid)}
      {:error, reason} -> %{id: start.id, error: inspect(reason, limit: 16)}
    end
  end

  defp maybe_start(%{start: start}, _outcome), do: %{id: start.id, error: "rollout_not_live"}
end
