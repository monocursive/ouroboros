defmodule Ouroboros.Wasm.Forge do
  @moduledoc """
  Turns a Cargo project on the guest SDK into a signed lane-W artifact (docs/WASM.md §7.7).

  `Ouroboros.Upgrade.Forge` is this module's shape in lane B: validate before you compile,
  compile somewhere that cannot reach the cluster, hold the product to the rules the
  loading node will re-check, and only then allocate a number and ask for a signature. What
  differs is what "somewhere" means. Lane B's build peer is a separate BEAM with no
  distribution — isolation from the *cluster*, not from the machine — and its own moduledoc
  says compiling hostile source needs a container around it. A Cargo build is arbitrary code
  at build time by construction (build scripts, proc macros, `include!`), so this lane does
  what that sentence asks for: the subprocess runs under `Ouroboros.Provider.Native.Sandbox`,
  the same OS sandbox the native agent's shell runs in, with no network, writes confined to a
  scratch directory and the registry cache, and a wall-clock ceiling.

  ## Three fences, and none of them is "we read the source"

  Nothing here reads a line of Rust and decides it is safe. What is enforced is narrower and
  checkable (D18, D19):

    * **The lock pin.** `Cargo.lock`, minus this project's own entry, must be byte-identical
      to the SDK's own resolved lock. So the dependency set is exactly the SDK's — the same
      crates, the same versions, the same checksums — and the only code that runs at build
      time is the SDK's own proc macros, which this repository already builds on every
      `make wasm-examples`.
    * **The file allow-list.** `Cargo.toml`, `Cargo.lock`, `src/**.rs`, an optional
      `README.md`, and nothing else: at most 32 files and a
      mebibyte in total, every path
      relative and free of `..`, no symlinks, and no `build.rs` — checked by name *and* by
      refusing the `[package] build` key that would give one power, because `src/build.rs`
      is otherwise a file the allow-list admits.
    * **The sandbox.** A `Sandbox.builder_policy/1`: deny-by-default on **reads** as well as
      on writes, so a build reads the toolchain, the SDK, the `wit` world file and its own
      directories and nothing else — `include_str!` of anything else fails at compile time,
      in whichever words the backend refuses a read with (`Operation not permitted` from
      Seatbelt, `No such file or directory` from a bubblewrap namespace,
      `Permission denied` from `ouro-sandbox`'s Landlock read set). No network
      (`--offline` as well, so a cold cache is a refusal rather than a fetch), writes only
      into the build directory, the node-local cargo home and a private `TMPDIR` — and, on
      Linux, `/dev/null` and nothing else under `/dev` — a five-minute ceiling, bounded
      output.

  The manifest is read twice. First by a deliberately small scanner that refuses every line it
  cannot classify — the set of manifests this lane accepts is the scaffold's shape, so
  `[patch]`, `[replace]`, a `[profile.release]` that is not the SDK's, a second dependency or a
  multi-line string is a refusal rather than a feature. Then by `Toml`, the parser this
  repository already reads `ouroboros.toml` with, and the two must produce **the same
  document**. A scanner that is not a TOML parser is exactly the thing an author could write a
  manifest to fool: something it reads as harmless and cargo reads as powerful. The
  disagreement is the refusal, so that gap has to be a TOML feature *neither* reader
  understands rather than one.

  ## And a fourth thing, which is about *which* machine

  The three fences bound what a build may do. `placement/3` decides where it happens, and it is
  a check rather than advice (D29, contract C14): a `:signer`-role node refuses to forge at all,
  because the two things this lane keeps apart are arbitrary code at build time and the key that
  makes bytes admissible everywhere. `config :ouroboros, :wasm_forge_placement` is `:local` by
  default — a forge runs where the effect lands, exactly as before — and `:builder` forwards one
  that landed elsewhere to a connected `:builder` node, under the same server-owned principal,
  where every fence above is that node's own.

  ## Why this node may read the imports of these bytes

  `Ouroboros.Wasm.Deploy.sign/2` never parses a component, because those bytes arrived from a
  socket and pointing the helper at unsigned input is what D15 exists to avoid. Here the node
  *built* the bytes, from source it validated, with a dependency set it pinned, inside its own
  sandbox — nobody chose them but this node. So the import list is read with the node's own
  helper (`Ouroboros.Wasm.Pool.inspect/2`, under the W7 bounds) instead of being declared,
  and it is still cross-checked against the manifest at stage like every other deploy.

  ## What comes out

  `forge/2` answers with the sign receipt plus the signed manifest, and writes the bundle
  into `<data_dir>/wasm/forged/` — the one durable thing this module owns, bounded to the
  newest few bundles. `deploy/3` reads that file back, verifies it is the artifact it was
  asked for, and hands it to `Ouroboros.Wasm.Deploy.deploy/3` unchanged. The component bytes
  never travel through an agent's state or an effect's audit trail; the artifact id and the
  digest do.
  """

  alias Ouroboros.Cluster
  alias Ouroboros.Provider.Native.Exec
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Bundle
  alias Ouroboros.Wasm.Deploy
  alias Ouroboros.Wasm.Pool
  alias Ouroboros.Wasm.Upload

  # C9's bounds. Thirty-two files and a mebibyte is a scaffold with room to grow a module
  # tree; it is not a vendored dependency, a fixture corpus, or a repository.
  @max_files 32
  @max_total_bytes 1024 * 1024
  @max_path_bytes 200
  @max_depth 6

  @default_timeout_ms 300_000
  @max_timeout_ms 300_000
  # What a forwarded forge waits beyond the build's own budget, so the builder's typed refusal
  # arrives instead of an opaque `:erpc` timeout. `Upgrade.Forge.BuildPeer`'s number, for the
  # same reason.
  @remote_slack 10_000

  @max_output_bytes 64 * 1024
  @reported_output_bytes 8 * 1024
  @forged_bundles 8
  @target "wasm32-wasip2"

  @signer_refusal "this node is in the :signer role, and a forge is arbitrary code at build " <>
                    "time (docs/WASM.md D18, D19). A build never runs beside the signing key: " <>
                    "forge on a :core or :builder node and deploy the bundle from there " <>
                    "(D29, contract C14)"

  @no_builder_refusal "config :ouroboros, :wasm_forge_placement is :builder and no connected " <>
                        "node running this runtime is in the :builder role. Connect one, or " <>
                        "set the placement back to :local to build where the effect lands (D29)"

  @manifest_file "Cargo.toml"
  @lock_file "Cargo.lock"
  @readme_file "README.md"
  @entry_file "src/lib.rs"
  # The operator's own proposal metadata (`Ouroboros.Runtime.Capabilities`), which lives
  # beside a workspace proposal and is not part of the project. It is bounded and
  # path-checked like every other file and then left behind: cargo never sees it, and it is
  # outside `source_sha256` so the same project forged from a workspace and from an agent's
  # inline files has the same provenance digest.
  @proposal_file "manifest.json"
  @guest_crate "ouroboros-guest"

  # The SDK's own resolved lock, embedded at compile time. It is the dependency set every
  # forged project is pinned to, and `@external_resource` means a change to it recompiles
  # this module rather than leaving a stale set behind.
  @sdk_lock_path Path.expand("../../../tui/wasm/guest/Cargo.lock", __DIR__)
  @external_resource @sdk_lock_path
  # Read, not defaulted: a build of this application without the SDK's lock beside it would
  # be a forge with nothing to pin a submitted project to, and the honest place to fail that
  # is the compile rather than the first refusal an operator cannot explain.
  @canonical_lock (case File.read(@sdk_lock_path) do
                     {:ok, contents} ->
                       contents

                     {:error, reason} ->
                       raise "cannot read the guest SDK's lock at #{@sdk_lock_path}: " <>
                               "#{:file.format_error(reason)}. `Ouroboros.Wasm.Forge` pins " <>
                               "every forged project to it, so this application does not " <>
                               "build without tui/wasm/guest beside it."
                   end)

  @sdk_default Path.expand("../../../tui/wasm/guest", __DIR__)

  # The scaffold's release profile, verbatim. A project may repeat it — cargo reads a
  # profile only from a workspace root, so every one of these projects has to — and may not
  # change it: `panic = "abort"` is what keeps the unwinder out, and the size-shaped
  # optimisation is what keeps the import list at exactly `log`.
  @release_profile %{
    "panic" => "abort",
    "lto" => true,
    "opt-level" => "s",
    "strip" => true,
    "codegen-units" => 1
  }

  @package_keys ~w(
    name version edition rust-version publish description license authors
    repository readme homepage documentation keywords categories
  )

  @editions ~w(2021 2024)

  @type input :: %{optional(:dir) => Path.t(), optional(:files) => %{String.t() => binary()}}

  @typedoc """
  Where a forge lands: here, on a named builder, or nowhere with the reason said out loud.
  """
  @type placement :: :local | {:forward, node()} | {:refuse, {atom(), String.t()}}

  @doc "The most files one forge input may carry."
  @spec max_files() :: pos_integer()
  def max_files, do: @max_files

  @doc "The most bytes one forge input may total."
  @spec max_total_bytes() :: pos_integer()
  def max_total_bytes, do: @max_total_bytes

  @doc "The SDK's resolved dependency lock, as this build pinned it."
  @spec canonical_lock() :: binary()
  def canonical_lock, do: @canonical_lock

  @doc """
  Validates, builds, reads, signs — and writes the bundle this node can later deploy.

  Required options: `:author`, the server-owned principal recorded as provenance. Optional:
  `:eval` (the signed evaluation spec, which lane W requires by default, D12),
  `:start_config`, `:name` (the capability this input must turn out to be), and the test
  seams `:sdk_path`,
  `:cargo_home`, `:cargo`, `:scratch_root`, `:forged_root`, `:upload_root`,
  `:signing_service`, `:signing_node`, `:epoch_nodes`, `:pool`, `:timeout_ms`, `:placement`,
  `:peers` and `:rpc`.

  `placement_here/1` decides where this runs before a byte is read: a `:signer` node refuses,
  and under `:builder` placement a forge that landed on a non-builder is forwarded to one
  (D29). Nothing below this line has happened when either of those answers.
  """
  @spec forge(input(), keyword()) :: {:ok, map()} | {:error, term()}
  def forge(input, opts \\ [])

  def forge(input, opts) when is_list(opts) do
    case placement_here(opts) do
      :local -> forge_here(input, opts)
      {:forward, target} -> forward(target, input, opts)
      {:refuse, {reason, why}} -> {:error, {:forge_refused, reason, why}}
    end
  end

  @doc false
  # The build itself, on whichever node is running this code. Named separately from `forge/2`
  # so a builder can never re-dispatch to a builder — `Ouroboros.Upgrade.Forge.BuildPeer` is
  # split for exactly that reason — and the placement question is therefore asked here with the
  # one setting that cannot forward. What it still answers is the role check: the node that
  # runs the build is the node that must not be holding a signing key (C14, D29).
  @spec forge_here(input(), keyword()) :: {:ok, map()} | {:error, term()}
  def forge_here(input, opts) when is_list(opts) do
    case placement(Cluster.role(), :local, []) do
      :local -> run_forge(input, opts)
      {:refuse, {reason, why}} -> {:error, {:forge_refused, reason, why}}
    end
  end

  defp run_forge(input, opts) do
    with {:ok, author} <- author(opts),
         {:ok, project} <- collect(input),
         {:ok, project} <- validate(project, opts),
         {:ok, built} <- build(project, opts) do
      try do
        with {:ok, report} <- inspect_product(built, opts),
             {:ok, receipt} <- sign(project, built, report, author, opts),
             {:ok, bundle} <- bundle(receipt, built),
             {:ok, decoded} <- Bundle.decode(bundle),
             {:ok, path} <- retain(decoded.artifact, bundle, opts) do
          {:ok, forged(project, built, receipt, decoded.artifact, path)}
        end
      after
        _ = File.rm_rf(built.directory)
      end
    end
  end

  @doc """
  Everything `forge/2` checks before it signs, and a dry build where the toolchain allows one.

  Never signs, never allocates an epoch, never writes a bundle. A preview that built is not
  a prepared deploy — it is the same statement `Ouroboros.Upgrade.Forge.preview/2` makes.

  `build?: false` stops after validation, which is what a caller asking only "would this be
  accepted" wants and what a node with no toolchain can answer.

  `placement` reports where a forge of this input would run (D29), so an operator learns that
  this node refuses or forwards *before* they spend a build finding out.
  """
  @spec preview(input(), keyword()) :: {:ok, map()} | {:error, term()}
  def preview(input, opts \\ []) when is_list(opts) do
    placement = placement_here(opts)

    with {:ok, project} <- collect(input),
         {:ok, project} <- validate(project, opts) do
      {:ok,
       %{
         name: project.name,
         version: project.version,
         files: Map.keys(project.files) |> Enum.sort(),
         bytes: project.bytes,
         source_sha256: project.sha256,
         lock: :sdk_lock,
         toolchain: toolchain(opts),
         placement: placement_report(placement),
         build: preview_build(project, opts, placement)
       }}
    end
  end

  # A preview builds only where a forge would. On a `:signer` that is nowhere at all; on a node
  # whose forge would be forwarded it is the *builder's* toolchain that decides, and a dry build
  # run here would be an answer about a machine that is not going to do the work.
  defp preview_build(project, opts, :local) do
    if Keyword.get(opts, :build?, true), do: dry_build(project, opts), else: :skipped
  end

  defp preview_build(_project, _opts, _elsewhere), do: :not_placed_here

  @doc """
  Deploys a bundle this node forged, named by the artifact it produced.

  The bundle is read back from `<data_dir>/wasm/forged/`, held to the artifact it is supposed
  to be, staged through `Ouroboros.Wasm.Upload` and handed to `Ouroboros.Wasm.Deploy.deploy/3`,
  which verifies the signature against this node's own trust policy before anything is stored.
  """
  @spec deploy(Wasm.Artifact.t(), [node()], keyword()) :: {:ok, map()} | {:error, term()}
  def deploy(artifact, nodes, opts \\ [])

  def deploy(%Wasm.Artifact{} = artifact, nodes, opts)
      when is_list(nodes) and nodes != [] and is_list(opts) do
    with {:ok, bundle} <- read_bundle(artifact, opts),
         {:ok, upload} <- stage(bundle, opts) do
      Deploy.deploy(upload, nodes, deploy_opts(opts))
    end
  end

  def deploy(artifact, nodes, _opts),
    do: {:error, {:invalid_deploy_request, describe({artifact, nodes})}}

  @doc """
  What this node can build a component with, asked rather than assumed.

  `cargo`, whether the `#{@target}` target is installed, where the registry cache is and
  whether it holds every crate the SDK's lock names, and which OS sandbox the build would run
  under. `capabilities.preview` reports it so an operator learns a builder is not ready
  before an admit tells them the same thing more expensively.
  """
  @spec toolchain(keyword()) :: map()
  def toolchain(opts \\ []) do
    cargo = cargo(opts)
    home = cargo_home(opts)

    %{
      cargo: cargo,
      target: @target,
      target_installed?: target_installed?(cargo, opts),
      cargo_home: home,
      cache: cache_state(home),
      sandbox: Sandbox.label(Sandbox.detect()),
      sdk: sdk_or_nil(opts)
    }
  end

  defp sdk_or_nil(opts) do
    case sdk_root(opts) do
      {:ok, root} -> root
      {:error, _absent} -> nil
    end
  end

  ## ------------------------------------------------------------------- placement

  @doc """
  Where a forge of this input would run, decided before anything is read (D29, contract C14).

  Pure, and total over the three roles: this node's role, the `:wasm_forge_placement` setting,
  and the connected nodes with the roles `Ouroboros.Cluster` reports for them. Pure because
  "would this node build, forward, or refuse" is a question an operator asks and a test pins,
  and a decision taken inside the build path is one nobody can ask about without running a
  build.

    * A **`:signer`** node refuses, whatever the setting and whatever the fleet looks like. A
      Cargo build is arbitrary code at build time (D18, D19) and the signing key is on that
      node; those two do not share a machine. This is the check D18 said did not exist.
    * **`:local`** — the default — builds where the effect lands, which is what this lane did
      before this decision. An operator who wants a dedicated builder still gets one by putting
      the toolchain, the warmed cache and the `:forge` grant on that node.
    * **`:builder`** forwards a forge that landed on a non-builder node to a connected
      `:builder`, and refuses `:no_builder_node` when there is none — never falling back to
      building here, because "build it locally instead" is the exact outcome the setting was
      chosen to prevent. A `:builder` node under `:builder` builds here: a builder that
      re-dispatched to a builder is a loop.

  The forward target is the lowest node name among the connected builders, so the decision is
  one a test can pin rather than whichever peer answered first. Role here is what `Cluster`
  reports and is a *placement* fact, not a boundary: a hostile connected node has `:erpc`
  authority over this one regardless (`Ouroboros.Cluster`, "Limits"). What this stops is a
  build landing on the machine holding the key.

  An unrecognized setting is a refusal rather than a fallback to `:local`: an operator who
  typed `:buidler` asked for a forge *not* to run here, and reading their typo as the default
  would build on precisely the node they were moving the build off.
  """
  @spec placement(Cluster.role(), term(), [{node(), Cluster.role()}]) :: placement()
  def placement(role, setting, peers)

  def placement(:signer, _setting, _peers), do: {:refuse, {:signer_node, @signer_refusal}}
  def placement(_role, :local, _peers), do: :local
  def placement(:builder, :builder, _peers), do: :local

  def placement(_role, :builder, peers) when is_list(peers) do
    peers
    |> Enum.flat_map(fn
      {target, :builder} when is_atom(target) and not is_nil(target) -> [target]
      _other -> []
    end)
    |> Enum.sort()
    |> case do
      [target | _rest] -> {:forward, target}
      [] -> {:refuse, {:no_builder_node, @no_builder_refusal}}
    end
  end

  def placement(_role, other, _peers),
    do:
      {:refuse,
       {:invalid_placement,
        "config :ouroboros, :wasm_forge_placement is #{describe(other)}; it is :local or " <>
          ":builder, and a value that is neither is refused rather than read as the default"}}

  @doc """
  This node's placement decision, read from its role, its configuration and the fleet.

  `:placement` overrides the configured setting for one call and `:peers` the fleet reading,
  which is how a test pins the impure half against a real `Ouroboros.Cluster.role/0` without a
  role-shaped cluster. Neither reaches this function from a socket: `forge/2`'s options are
  built by the effect surface and by `Ouroboros.Runtime.Capabilities`, the same place `:cargo`
  and `:scratch_root` come from.
  """
  @spec placement_here(keyword()) :: placement()
  def placement_here(opts \\ []) when is_list(opts) do
    setting = placement_setting(opts)
    placement(Cluster.role(), setting, peer_roles(setting, opts))
  end

  @doc "The placement decision in the shape `capabilities.preview` puts on the wire."
  @spec placement_report(placement()) :: map()
  def placement_report(:local), do: %{decision: :local, node: node()}
  def placement_report({:forward, target}), do: %{decision: :forward, node: target}

  def placement_report({:refuse, {reason, why}}),
    do: %{decision: :refuse, reason: reason, detail: why}

  defp placement_setting(opts) do
    Keyword.get_lazy(opts, :placement, fn ->
      Application.get_env(:ouroboros, :wasm_forge_placement, :local)
    end)
  end

  # The cluster is asked only where the answer can change the decision. `:local` builds here
  # whatever the fleet looks like, and `Cluster.nodes_by_role/1` is an `:erpc` multicall with a
  # five-second ceiling — putting one in front of every default forge would be a probe no
  # decision depends on.
  defp peer_roles(setting, opts) do
    Keyword.get_lazy(opts, :peers, fn -> connected_roles(setting) end)
  end

  defp connected_roles(:builder),
    do: Enum.map(Cluster.nodes_by_role(:builder), &{&1, :builder})

  defp connected_roles(_other), do: []

  # The same input, the same attrs and the same server-owned principal, under the origin's own
  # build budget so the builder's configuration cannot widen it — and `forge_here/2` rather than
  # `forge/2` as the entry point, so the far end cannot forward again. Everything the builder
  # does with it is its own: its sandbox, its cache, its role check, its signing service.
  defp forward(target, input, opts) do
    budget = build_timeout(opts)
    rpc = Keyword.get(opts, :rpc, :erpc)
    remote = opts |> Keyword.delete(:rpc) |> Keyword.put(:timeout_ms, budget)

    rpc.call(target, __MODULE__, :forge_here, [input, remote], budget + @remote_slack)
  catch
    kind, reason -> {:error, {:forge_forward_failed, target, {kind, describe(reason)}}}
  end

  ## ------------------------------------------------------------------ collection

  # A directory is walked with `File.lstat/1` at every step and a symlink is a refusal, not
  # a thing to follow: the whole point of the allow-list is that the bytes that reach the
  # scratch directory are the bytes that were named.
  defp collect(%{dir: dir}) when is_binary(dir) and dir != "" do
    case File.lstat(dir) do
      {:ok, %File.Stat{type: :directory}} ->
        with {:ok, files} <- walk(dir, "", %{}, 0) do
          {:ok, %{files: files}}
        end

      {:ok, %File.Stat{type: type}} ->
        {:error, {:invalid_forge_input, {:not_a_directory, type}}}

      {:error, reason} ->
        {:error, {:forge_input_unreadable, reason}}
    end
  end

  defp collect(%{files: files}) when is_map(files) and map_size(files) > 0 do
    if map_size(files) > @max_files do
      {:error, {:too_many_files, map_size(files), @max_files}}
    else
      Enum.reduce_while(files, {:ok, %{}}, fn
        {path, contents}, {:ok, acc} when is_binary(path) and is_binary(contents) ->
          {:cont, {:ok, Map.put(acc, path, contents)}}

        {path, _contents}, {:ok, _acc} ->
          {:halt, {:error, {:invalid_forge_input, {:file, describe(path)}}}}
      end)
      |> case do
        {:ok, collected} -> {:ok, %{files: collected}}
        {:error, _reason} = error -> error
      end
    end
  end

  defp collect(input), do: {:error, {:invalid_forge_input, describe(input)}}

  defp walk(root, relative, acc, depth) when depth <= @max_depth do
    directory = if relative == "", do: root, else: Path.join(root, relative)

    case File.ls(directory) do
      {:ok, entries} ->
        entries
        |> Enum.sort()
        |> Enum.reduce_while({:ok, acc}, fn entry, {:ok, acc} ->
          case walk_entry(root, relative, entry, acc, depth) do
            {:ok, acc} -> {:cont, {:ok, acc}}
            {:error, _reason} = error -> {:halt, error}
          end
        end)

      {:error, reason} ->
        {:error, {:forge_input_unreadable, reason}}
    end
  end

  defp walk(_root, relative, _acc, _depth), do: {:error, {:path_too_deep, relative}}

  defp walk_entry(root, relative, entry, acc, depth) do
    path = if relative == "", do: entry, else: relative <> "/" <> entry
    absolute = Path.join(root, path)

    cond do
      map_size(acc) >= @max_files ->
        {:error, {:too_many_files, map_size(acc) + 1, @max_files}}

      true ->
        case File.lstat(absolute) do
          {:ok, %File.Stat{type: :directory}} -> walk(root, path, acc, depth + 1)
          {:ok, %File.Stat{type: :regular}} -> read_entry(absolute, path, acc)
          {:ok, %File.Stat{type: :symlink}} -> {:error, {:symlink_refused, path}}
          {:ok, %File.Stat{type: type}} -> {:error, {:irregular_file, path, type}}
          {:error, reason} -> {:error, {:forge_input_unreadable, path, reason}}
        end
    end
  end

  defp read_entry(absolute, path, acc) do
    case File.read(absolute) do
      {:ok, contents} -> {:ok, Map.put(acc, path, contents)}
      {:error, reason} -> {:error, {:forge_input_unreadable, path, reason}}
    end
  end

  ## ------------------------------------------------------------------ validation

  defp validate(%{files: files}, opts) do
    with :ok <- bound(files),
         :ok <- Enum.reduce_while(files, :ok, &validate_path/2),
         :ok <- required(files),
         {:ok, manifest} <- manifest(Map.fetch!(files, @manifest_file)),
         :ok <- declared_name(manifest, opts),
         :ok <- lock(Map.fetch!(files, @lock_file), manifest) do
      project = Map.delete(files, @proposal_file)

      {:ok,
       %{
         files: files,
         project: project,
         name: manifest.name,
         version: manifest.version,
         bytes: total(files),
         sha256: source_digest(project)
       }}
    end
  end

  # A caller that already knows what this capability is called says so, and the package name
  # has to be that name. The operator surface knows it from the proposal's own manifest, and
  # a disagreement there is two names for one thing — refused before a build rather than
  # after one, because the build is the expensive half and the name is not a build product.
  defp declared_name(manifest, opts) do
    case Keyword.get(opts, :name) do
      nil -> :ok
      name when name == :erlang.map_get(:name, manifest) -> :ok
      other -> {:error, {:name_mismatch, describe(other), manifest.name}}
    end
  end

  # Bytes only. The **count** is bounded by `collect/1` — by its own guard for an inline map
  # and by `walk_entry/5` for a directory, which refuses at the thirty-third entry rather
  # than after reading a repository into memory — and a second count here was a check no
  # input could reach, which is the same thing as no check at all.
  defp bound(files) do
    total = total(files)

    if total > @max_total_bytes,
      do: {:error, {:input_too_large, total, @max_total_bytes}},
      else: :ok
  end

  defp total(files),
    do: Enum.reduce(files, 0, fn {_path, contents}, sum -> sum + byte_size(contents) end)

  # Path first, then the allow-list. An escaping path is refused for escaping rather than
  # for not being on the list, because those are two different things to tell somebody.
  defp validate_path({path, _contents}, :ok) do
    segments = String.split(path, "/")

    cond do
      byte_size(path) > @max_path_bytes ->
        {:halt, {:error, {:path_too_long, describe(path)}}}

      String.contains?(path, "\0") ->
        {:halt, {:error, {:invalid_path, describe(path)}}}

      String.contains?(path, "\\") ->
        {:halt, {:error, {:invalid_path, describe(path)}}}

      Path.type(path) != :relative ->
        {:halt, {:error, {:absolute_path, describe(path)}}}

      Enum.any?(segments, &(&1 in ["", ".", ".."])) ->
        {:halt, {:error, {:path_escape, describe(path)}}}

      length(segments) > @max_depth ->
        {:halt, {:error, {:path_too_deep, describe(path)}}}

      Path.basename(path) == "build.rs" ->
        {:halt, {:error, {:build_script_refused, path}}}

      allowed?(path, segments) ->
        {:cont, :ok}

      true ->
        {:halt, {:error, {:file_not_allowed, path}}}
    end
  end

  defp allowed?(path, segments) do
    path in [@manifest_file, @lock_file, @readme_file, @proposal_file] or
      (hd(segments) == "src" and length(segments) > 1 and String.ends_with?(path, ".rs"))
  end

  defp required(files) do
    missing = Enum.reject([@manifest_file, @lock_file, @entry_file], &Map.has_key?(files, &1))
    if missing == [], do: :ok, else: {:error, {:missing_files, missing}}
  end

  ## The manifest

  # Not a TOML parser: a scanner over the scaffold's shape that refuses every line it cannot
  # classify. The set of manifests this lane builds is small and known, so "I do not
  # understand this line" and "this manifest is not allowed" are the same answer.
  defp manifest(contents) do
    with {:ok, sections} <- scan(contents),
         :ok <- agreed?(contents, sections),
         :ok <- known_sections(sections),
         {:ok, package} <- section(sections, "package"),
         :ok <- package_keys(package),
         {:ok, name} <- package_name(package),
         {:ok, version} <- package_version(package),
         :ok <- edition(package),
         :ok <- lib_section(sections),
         :ok <- workspace_section(sections),
         :ok <- dependencies(sections),
         :ok <- profile(sections) do
      {:ok, %{name: name, version: version}}
    end
  end

  defp scan(contents) when byte_size(contents) <= @max_total_bytes do
    contents
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.reduce_while({:ok, {nil, %{}}}, fn {line, number}, {:ok, {current, sections}} ->
      case scan_line(strip_comment(line), current, sections, number) do
        {:ok, state} -> {:cont, {:ok, state}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, {_current, sections}} -> {:ok, sections}
      {:error, _reason} = error -> error
    end
  end

  defp scan(_contents), do: {:error, {:invalid_manifest, :too_large}}

  # The differential check. `Toml` is what `ouroboros.toml` is read with, so it is the reader
  # whose interpretation of a manifest this repository already trusts; the scanner above is
  # what enforces the allow-list. They must describe the same document, or the allow-list is
  # being applied to something other than what cargo will build.
  defp agreed?(contents, sections) do
    case Toml.decode(contents) do
      {:ok, decoded} ->
        if decoded == nest(sections),
          do: :ok,
          else: {:error, {:manifest_disagreement, decoded |> Map.keys() |> Enum.sort()}}

      {:error, reason} ->
        {:error, {:invalid_manifest, describe(reason)}}
    end
  end

  defp nest(sections) do
    Enum.reduce(sections, %{}, fn {name, values}, acc ->
      case String.split(name, ".") do
        [leaf] ->
          Map.put(acc, leaf, values)

        [head | rest] ->
          Map.update(acc, head, nest_path(rest, values), &put_path(&1, rest, values))
      end
    end)
  end

  defp nest_path([leaf], values), do: %{leaf => values}
  defp nest_path([head | rest], values), do: %{head => nest_path(rest, values)}

  defp put_path(existing, path, values) when is_map(existing) do
    case path do
      [leaf] ->
        Map.put(existing, leaf, values)

      [head | rest] ->
        Map.update(existing, head, nest_path(rest, values), &put_path(&1, rest, values))
    end
  end

  defp scan_line(line, current, sections, number) do
    trimmed = String.trim(line)

    cond do
      trimmed == "" ->
        {:ok, {current, sections}}

      String.starts_with?(trimmed, "[[") ->
        {:error, {:invalid_manifest, {:array_of_tables, number}}}

      String.starts_with?(trimmed, "[") and String.ends_with?(trimmed, "]") ->
        name = trimmed |> String.slice(1..-2//1) |> String.trim()

        if Map.has_key?(sections, name) do
          {:error, {:invalid_manifest, {:duplicate_section, name}}}
        else
          {:ok, {name, Map.put(sections, name, %{})}}
        end

      is_nil(current) ->
        {:error, {:invalid_manifest, {:key_outside_section, number}}}

      true ->
        with {:ok, key, value} <- key_value(trimmed, number) do
          {:ok, {current, put_in(sections[current][key], value)}}
        end
    end
  end

  defp key_value(line, number) do
    case String.split(line, "=", parts: 2) do
      [key, value] ->
        key = key |> String.trim() |> String.trim("\"")

        with {:ok, parsed} <- value(String.trim(value), number) do
          if key == "",
            do: {:error, {:invalid_manifest, {:empty_key, number}}},
            else: {:ok, key, parsed}
        end

      _other ->
        {:error, {:invalid_manifest, {:unreadable_line, number}}}
    end
  end

  defp value("true", _number), do: {:ok, true}
  defp value("false", _number), do: {:ok, false}

  defp value(text, number) do
    cond do
      String.starts_with?(text, "\"") -> string_value(text, number)
      String.starts_with?(text, "[") -> array_value(text, number)
      String.starts_with?(text, "{") -> table_value(text, number)
      Regex.match?(~r/\A-?[0-9]+\z/, text) -> {:ok, String.to_integer(text)}
      true -> {:error, {:invalid_manifest, {:unreadable_value, number}}}
    end
  end

  defp string_value(text, number) do
    if Regex.match?(~r/\A"[^"\\\n]*"\z/, text) do
      {:ok, String.slice(text, 1..-2//1)}
    else
      {:error, {:invalid_manifest, {:unreadable_value, number}}}
    end
  end

  defp array_value(text, number) do
    if String.ends_with?(text, "]") do
      text
      |> String.slice(1..-2//1)
      |> String.split(",")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.reduce_while({:ok, []}, fn element, {:ok, acc} ->
        case string_value(element, number) do
          {:ok, parsed} -> {:cont, {:ok, acc ++ [parsed]}}
          {:error, _reason} = error -> {:halt, error}
        end
      end)
    else
      {:error, {:invalid_manifest, {:unreadable_value, number}}}
    end
  end

  defp table_value(text, number) do
    if String.ends_with?(text, "}") do
      text
      |> String.slice(1..-2//1)
      |> String.split(",")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.reduce_while({:ok, %{}}, fn entry, {:ok, acc} ->
        case key_value(entry, number) do
          {:ok, key, parsed} -> {:cont, {:ok, Map.put(acc, key, parsed)}}
          {:error, _reason} = error -> {:halt, error}
        end
      end)
    else
      {:error, {:invalid_manifest, {:unreadable_value, number}}}
    end
  end

  # A `#` inside a string is text; a `#` outside one starts a comment. Walking the line is
  # what tells them apart, and a description containing a hash is not a manifest this lane
  # should be refusing.
  defp strip_comment(line), do: strip_comment(line, <<>>, false)

  defp strip_comment(<<>>, acc, _in_string?), do: acc
  defp strip_comment(<<"#", _rest::binary>>, acc, false), do: acc

  defp strip_comment(<<"\"", rest::binary>>, acc, in_string?),
    do: strip_comment(rest, acc <> "\"", not in_string?)

  defp strip_comment(<<character::utf8, rest::binary>>, acc, in_string?),
    do: strip_comment(rest, acc <> <<character::utf8>>, in_string?)

  defp strip_comment(<<byte, rest::binary>>, acc, in_string?),
    do: strip_comment(rest, acc <> <<byte>>, in_string?)

  @known_sections ~w(workspace package lib dependencies profile.release)

  defp known_sections(sections) do
    case Enum.reject(Map.keys(sections), &(&1 in @known_sections)) do
      [] -> :ok
      unknown -> {:error, {:manifest_section_not_allowed, Enum.sort(unknown)}}
    end
  end

  defp section(sections, name) do
    case Map.fetch(sections, name) do
      {:ok, values} -> {:ok, values}
      :error -> {:error, {:missing_manifest_section, name}}
    end
  end

  defp package_keys(package) do
    case Enum.reject(Map.keys(package), &(&1 in @package_keys)) do
      [] -> :ok
      unknown -> {:error, {:manifest_key_not_allowed, "package", Enum.sort(unknown)}}
    end
  end

  # The cargo package name *is* the capability's name: one identity, derived once, so the
  # product's filename and the signed manifest's name cannot disagree.
  defp package_name(package) do
    case Map.get(package, "name") do
      name when is_binary(name) ->
        if Wasm.Artifact.name?(name) and Regex.match?(~r/\A[a-z0-9][a-z0-9_-]*\z/, name),
          do: {:ok, name},
          else: {:error, {:invalid_package_name, describe(name)}}

      other ->
        {:error, {:invalid_package_name, describe(other)}}
    end
  end

  defp package_version(package) do
    case Map.get(package, "version") do
      version when is_binary(version) ->
        if Regex.match?(~r/\A[0-9A-Za-z.\-+]{1,32}\z/, version),
          do: {:ok, version},
          else: {:error, {:invalid_package_version, describe(version)}}

      other ->
        {:error, {:invalid_package_version, describe(other)}}
    end
  end

  defp edition(package) do
    case Map.get(package, "edition") do
      edition when edition in @editions -> :ok
      other -> {:error, {:invalid_edition, describe(other)}}
    end
  end

  # `[lib] name` would move the file cargo emits away from the package name, which is the
  # one string this module uses to find the product. `crate-type` must be the component's.
  defp lib_section(sections) do
    case Map.get(sections, "lib") do
      %{"crate-type" => ["cdylib"]} = lib when map_size(lib) == 1 -> :ok
      other -> {:error, {:invalid_lib_section, describe(other)}}
    end
  end

  defp workspace_section(sections) do
    case Map.get(sections, "workspace") do
      nil -> :ok
      empty when empty == %{} -> :ok
      other -> {:error, {:invalid_workspace_section, describe(other)}}
    end
  end

  # One dependency, and it is the SDK. Anything else is refused here as well as by the lock:
  # a second dependency changes this project's own entry in `Cargo.lock`, so the two checks
  # agree, and the one that names the crate is the one worth reading.
  defp dependencies(sections) do
    case Map.get(sections, "dependencies") do
      %{@guest_crate => %{"path" => path} = table} = deps
      when map_size(deps) == 1 and map_size(table) == 1 and is_binary(path) ->
        :ok

      # `features`, `version`, `git`, `default-features` — every one of them changes what
      # cargo resolves or how it builds, and the path is replaced by this module anyway, so
      # the honest shape of this dependency is one key.
      %{@guest_crate => table} = deps when map_size(deps) == 1 and is_map(table) ->
        {:error,
         {:invalid_guest_dependency,
          table |> Map.keys() |> Enum.reject(&(&1 == "path")) |> Enum.sort()}}

      %{@guest_crate => _other} = deps when map_size(deps) == 1 ->
        {:error, {:invalid_guest_dependency, "the SDK is reached by `path`"}}

      other when is_map(other) ->
        {:error,
         {:dependency_not_allowed,
          other |> Map.keys() |> Enum.reject(&(&1 == @guest_crate)) |> Enum.sort()}}

      nil ->
        {:error, {:missing_manifest_section, "dependencies"}}
    end
  end

  defp profile(sections) do
    case Map.get(sections, "profile.release") do
      @release_profile -> :ok
      other -> {:error, {:profile_override_refused, describe(other)}}
    end
  end

  ## The lock

  # Byte-identity, with exactly one hole in it: this project's own entry, which carries its
  # name and cannot be in the SDK's lock. Everything else — every crate, version, checksum
  # and dependency edge — must be the bytes cargo resolved for the SDK itself.
  defp lock(contents, manifest) when byte_size(contents) <= @max_total_bytes do
    if String.ends_with?(contents, "\n") do
      compare(entries(contents), manifest)
    else
      {:error, {:lock_not_the_sdk_lock, :unterminated}}
    end
  end

  defp lock(_contents, _manifest), do: {:error, {:lock_not_the_sdk_lock, :too_large}}

  defp compare(entries, manifest) do
    expected = String.trim_trailing(root_entry(manifest), "\n")

    case Enum.split_with(entries, &root_entry?(&1, manifest.name)) do
      {[^expected], rest} ->
        if rest == entries(@canonical_lock),
          do: :ok,
          else: {:error, {:lock_not_the_sdk_lock, :dependencies}}

      {[other], _rest} ->
        {:error, {:lock_not_the_sdk_lock, {:root_entry, describe(other)}}}

      {[], _rest} ->
        {:error, {:lock_not_the_sdk_lock, {:no_entry_for, manifest.name}}}

      {_many, _rest} ->
        {:error, {:lock_not_the_sdk_lock, {:duplicate_entry, manifest.name}}}
    end
  end

  # A lock is a header and a run of `[[package]]` blocks separated by one blank line. Splitting
  # on the separator and trimming what it consumed is what makes "byte-identical apart from
  # this project's own entry" something a comparison can say.
  defp entries(text),
    do: text |> String.split("\n\n") |> Enum.map(&String.trim_trailing(&1, "\n"))

  defp root_entry?(segment, name) do
    String.starts_with?(segment, "[[package]]\n") and
      String.contains?(segment <> "\n", "\nname = \"" <> name <> "\"\n") and
      not String.contains?(segment, "\nsource = ")
  end

  defp root_entry(%{name: name, version: version}) do
    """
    [[package]]
    name = "#{name}"
    version = "#{version}"
    dependencies = [
     "#{@guest_crate}",
    ]
    """
  end

  # A digest over the validated input, not over a directory listing: the same files in the
  # same bytes produce the same `source_sha256` inside the signed manifest, whether they
  # arrived inline or from a workspace.
  defp source_digest(files) do
    files
    |> Enum.sort()
    |> Enum.reduce(:crypto.hash_init(:sha256), fn {path, contents}, hash ->
      :crypto.hash_update(
        hash,
        <<byte_size(path)::32, path::binary, byte_size(contents)::32, contents::binary>>
      )
    end)
    |> :crypto.hash_final()
    |> Base.encode16(case: :lower)
  end

  ## ----------------------------------------------------------------------- build

  defp build(project, opts) do
    with {:ok, root} <- scratch_root(opts),
         {:ok, sdk} <- sdk_root(opts),
         {:ok, cargo} <- require_cargo(opts),
         {:ok, home} <- require_cargo_home(opts),
         :ok <- warm?(home) do
      directory = Path.join(root, "forge-" <> unique())

      case (with {:ok, directory} <- prepared(directory),
                 :ok <- materialize(project, directory, sdk),
                 {:ok, output} <- run_cargo(cargo, directory, home, sdk, opts),
                 {:ok, bytes, path} <- product(project, directory) do
              {:ok, %{bytes: bytes, path: path, output: output, directory: directory}}
            end) do
        {:ok, built} ->
          {:ok, built}

        {:error, _reason} = error ->
          _ = File.rm_rf(directory)
          error
      end
    end
  end

  # Created and then canonicalized, in that order and before anything else touches it. A
  # sandbox profile names real paths: on macOS the temporary and data directories both reach
  # this module through a symlink (`/var/folders/…` -> `/private/var/folders/…`), and a
  # writable root written in the other spelling is a rule the kernel matches nothing against
  # — which is a build denied every write it makes, including its own object files.
  defp prepared(directory) do
    with :ok <- File.mkdir_p(directory),
         {:ok, canonical} <- Ouroboros.Workspace.Path.canonicalize(directory) do
      {:ok, canonical}
    else
      {:error, reason} -> {:error, {:scratch_unwritable, directory, reason}}
    end
  end

  defp materialize(project, directory, sdk) do
    Enum.reduce_while(project.project, :ok, fn {path, contents}, :ok ->
      target = Path.join(directory, path)
      contents = if path == @manifest_file, do: point_at_sdk(contents, sdk), else: contents

      with :ok <- File.mkdir_p(Path.dirname(target)),
           :ok <- File.write(target, contents, [:binary]) do
        {:cont, :ok}
      else
        {:error, reason} -> {:halt, {:error, {:scratch_unwritable, path, reason}}}
      end
    end)
  end

  # The author's path to the SDK is a fact about the author's machine, and pointing this
  # node's build at it would be following a path a request chose. It is replaced, not
  # validated: the only checkout that may be linked against is the one this node configured.
  defp point_at_sdk(contents, sdk) do
    contents
    |> String.split("\n")
    |> Enum.map(fn line ->
      if Regex.match?(~r/\A\s*#{@guest_crate}\s*=/, line),
        do: ~s(#{@guest_crate} = { path = "#{sdk}" }),
        else: line
    end)
    |> Enum.join("\n")
  end

  defp run_cargo(cargo, directory, home, sdk, opts) do
    home = canonical(home)
    scope = %{root: directory}
    detection = Sandbox.detect()

    with {:ok, policy} <- sandbox_policy(cargo, directory, home, sdk, detection),
         {:ok, scratch} <- Sandbox.scratch() do
      policy = Sandbox.with_scratch(policy, scratch)

      try do
        with {:ok, {executable, args}} <- wrap(cargo, scope, policy, detection),
             {:ok, result} <- execute(executable, args, directory, home, policy, opts) do
          settle(result, Sandbox.label(detection))
        end
      after
        Sandbox.release(scratch)
      end
    end
  end

  defp canonical(path) do
    case Ouroboros.Workspace.Path.canonicalize(path) do
      {:ok, canonical} -> canonical
      {:error, _absent} -> path
    end
  end

  @doc """
  The policy this node would build under, or the reason it will not build at all.

  No backend is a refusal rather than a weaker posture, and so is a backend that cannot fence
  reads: a Cargo build is arbitrary code at build time, the sandbox is one of the three
  things that make this lane's claim true, and half a sandbox makes half of it. Public
  because "what would this build run under" is a question worth being able to ask without
  running one.

  All three backends can fence reads since W17, and the third is still asked rather than
  assumed. `Sandbox.fences_reads?/1` answers for `:ouro_sandbox` out of the probed helper's
  own `doctor` report, so the refusal below is no longer "this backend cannot" but "the
  binary installed on this node cannot" — an operator's remedy is a newer helper, and until
  they have one the node forges under bubblewrap or not at all.
  """
  @spec sandbox_policy(String.t(), Path.t(), Path.t(), Path.t(), Sandbox.detection()) ::
          {:ok, Sandbox.policy()} | {:error, term()}
  def sandbox_policy(cargo, directory, home, sdk, detection \\ Sandbox.detect())

  def sandbox_policy(cargo, directory, home, sdk, detection) do
    cond do
      detection.backend == :none ->
        {:error, {:sandbox_unavailable, {:no_backend, detection}}}

      not Sandbox.fences_reads?(detection) ->
        {:error,
         {:sandbox_cannot_fence_reads, detection.backend,
          "the #{Sandbox.label(detection)} at #{detection.executable || "(no path)"} " <>
            "cannot express a read allow-set, so a build under it could read anything the " <>
            "node can (docs/WASM.md D18, D26). A binary from before the allow-set reports " <>
            "no `read_allow_set` feature to `doctor` and is refused by that report rather " <>
            "than by its name — which is why this names the file: replace that one " <>
            "(`make sandbox`) or let detection fall through to bubblewrap."}}

      true ->
        {:ok,
         Sandbox.builder_policy(
           writable: [directory, home],
           readable: read_set(cargo, sdk)
         )}
    end
  end

  @doc """
  Everything a build may read beyond `Sandbox.platform_readable/0`, and why each one is here.

  Five roots, and the fence is that there is no sixth:

    * the **cargo executable's own directory**, because `process-exec` still has to read the
      binary — with rustup that is a shim, and the shim is what execs the real one;
    * the **rustup home**, which is where that real one and every library it links live;
    * the **guest SDK checkout**, which is the one path dependency a forged project has;
    * the **`wit` directory beside it**, because `wit_bindgen::generate!` reads
      `../wit` at macro-expansion time — a project that could not read it would fail to
      build, and a fence that let it read anything else to find it would not be one;
    * the **build directory and the cargo home**, which are writable and therefore readable.

  `Ouroboros.Wasm.Forge.read_set/2` is public so a test can assert on the list rather than on
  a profile, and so the answer to "what can a build read" is one function.
  """
  @spec read_set(String.t(), Path.t()) :: [Path.t()]
  def read_set(cargo, sdk) do
    [
      Path.dirname(cargo),
      rustup_home(),
      sdk,
      Path.expand("../wit", sdk)
    ]
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.map(&canonical/1)
    |> Enum.uniq()
  end

  defp rustup_home do
    case System.get_env("RUSTUP_HOME") do
      path when is_binary(path) and path != "" -> path
      _unset -> Path.join(System.user_home() || "/nonexistent", ".rustup")
    end
  end

  defp wrap(cargo, scope, policy, detection) do
    case Sandbox.wrap({:argv, cargo_argv(cargo)}, scope, policy, detection) do
      {:ok, wrapped} -> {:ok, wrapped}
      {:error, reason} -> {:error, {:sandbox_unavailable, reason}}
    end
  end

  # `--locked` refuses to touch the lock this module just pinned; `--offline` refuses to
  # reach an index even where a sandbox would have let it. Two answers to the same question,
  # from two places, because neither one is this module's to trust alone.
  defp cargo_argv(cargo),
    do: [cargo, "build", "--release", "--target", @target, "--locked", "--offline"]

  defp execute(executable, args, directory, home, policy, opts) do
    Exec.run(executable, args,
      cd: directory,
      env:
        Sandbox.env(policy) ++
          [{"CARGO_HOME", home}, {"CARGO_NET_OFFLINE", "true"}, {"CARGO_TERM_COLOR", "never"}],
      timeout_ms: build_timeout(opts),
      max_bytes: @max_output_bytes
    )
    |> case do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, {:build_failed, {:not_started, describe(reason)}}}
    end
  end

  defp settle(%{timed_out?: true}, _label), do: {:error, {:build_failed, {:timeout, :deadline}}}

  defp settle(%{status: 0, output: output}, _label), do: {:ok, clip(output)}

  defp settle(%{status: status, output: output}, label) do
    case Sandbox.backend_failure(label, output, status) do
      nil -> {:error, {:build_failed, {:exit, status, diagnosed(status, clip(output))}}}
      message -> {:error, {:sandbox_unavailable, {:backend_failed, label, message}}}
    end
  end

  # A build that fails and says nothing is the hardest kind to fix, and the first Linux run
  # of this lane produced exactly that: `{:exit, 134, ""}`, over and over, because the
  # namespace had re-bound `/dev` read-only and everything downstream of that died before it
  # could write a word. An empty output is now a sentence rather than an empty string, and a
  # status above 128 is the signal it stands for.
  defp diagnosed(status, "") when status > 128 and status < 192,
    do: "(no output; the build was killed by #{signal(status - 128)})"

  defp diagnosed(_status, ""), do: "(the build produced no output)"
  defp diagnosed(_status, output), do: output

  defp signal(6), do: "SIGABRT — a process aborted"
  defp signal(9), do: "SIGKILL"
  defp signal(11), do: "SIGSEGV"
  defp signal(15), do: "SIGTERM"
  defp signal(number), do: "signal #{number}"

  # Cargo's diagnostics are the author's text quoted back. Bounded, and never anything a
  # caller is invited to read as this node's own words.
  #
  # The **tail**, not the head: a build says `Compiling …` once per crate and then says why
  # it failed, so a bound that kept the first eight kibibytes kept forty lines of progress
  # and threw away the error. A sandbox denial is one line at the very end of that.
  defp clip(output) when byte_size(output) > @reported_output_bytes do
    "... truncated\n" <>
      binary_part(
        output,
        byte_size(output) - @reported_output_bytes,
        @reported_output_bytes
      )
  end

  defp clip(output), do: output

  defp product(project, directory) do
    file = String.replace(project.name, "-", "_") <> ".wasm"
    path = Path.join([directory, "target", @target, "release", file])

    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular, size: 0}} ->
        {:error, {:no_build_product, file, :empty}}

      {:ok, %File.Stat{type: :regular, size: size}} ->
        if size > Bundle.max_component_bytes() do
          {:error, {:component_too_large, size, Bundle.max_component_bytes()}}
        else
          case File.read(path) do
            {:ok, bytes} -> {:ok, bytes, path}
            {:error, reason} -> {:error, {:product_unreadable, reason}}
          end
        end

      {:ok, %File.Stat{type: type}} ->
        {:error, {:product_unreadable, type}}

      {:error, reason} ->
        {:error, {:no_build_product, file, reason}}
    end
  end

  defp dry_build(project, opts) do
    started = System.monotonic_time(:millisecond)

    case build(project, opts) do
      {:ok, built} ->
        _ = File.rm_rf(built.directory)

        %{
          outcome: :ok,
          ms: System.monotonic_time(:millisecond) - started,
          size: byte_size(built.bytes),
          component_sha256: Wasm.Artifact.digest(built.bytes)
        }

      {:error, reason} ->
        %{
          outcome: :failed,
          ms: System.monotonic_time(:millisecond) - started,
          # Wider than `describe/1`: this string is the whole of what an operator running
          # `capabilities.preview` is told about why a build did not happen, and a refusal
          # whose remedy was elided by an inspect limit is a refusal with its answer cut off.
          reason: inspect(reason, limit: 50, printable_limit: 1_000),
          # And the compiler's own words in a field of their own rather than escaped inside
          # that string. `inspect`'s printable limit cuts from the front, so a build whose
          # last line is the sandbox denial had exactly that line elided by the bound meant
          # to keep the refusal readable.
          output: build_output(reason)
        }
    end
  end

  @doc false
  @spec build_output(term()) :: String.t() | nil
  def build_output({:build_failed, {:exit, _status, output}}) when is_binary(output), do: output
  def build_output(_reason), do: nil

  ## ---------------------------------------------------------------------- imports

  # The one place this lane points the helper at bytes no signature covers, and the reason it
  # is allowed is in the moduledoc and in D18: this node built them.
  defp inspect_product(built, opts) do
    case Pool.inspect(built.path, pool(opts)) do
      {:ok, %{"imports" => imports, "world" => world} = report} when is_list(imports) ->
        cond do
          world != Wasm.world() -> {:error, {:world_not_supported, describe(world)}}
          not Enum.all?(imports, &is_binary/1) -> {:error, {:invalid_inspect_report, "imports"}}
          true -> {:ok, %{imports: Enum.sort(imports), world: world, report: report}}
        end

      {:ok, other} ->
        {:error, {:invalid_inspect_report, describe(other)}}

      {:error, reason} ->
        {:error, {:imports_unreadable, reason}}
    end
  end

  ## ------------------------------------------------------------------------- sign

  defp sign(project, built, report, author, opts) do
    with {:ok, upload} <- stage(built.bytes, opts) do
      %{
        upload: upload,
        name: project.name,
        author: author,
        imports: report.imports,
        language: "rust",
        source_sha256: project.sha256
      }
      |> put_present(:eval, Keyword.get(opts, :eval))
      |> put_present(:start_config, Keyword.get(opts, :start_config))
      |> Deploy.sign(sign_opts(opts))
    end
  end

  defp bundle(%{bundle_prefix: prefix}, built) do
    case Base.decode64(prefix) do
      {:ok, decoded} -> {:ok, decoded <> built.bytes}
      :error -> {:error, {:invalid_sign_receipt, :bundle_prefix}}
    end
  end

  defp forged(project, built, receipt, artifact, path) do
    receipt
    |> Map.merge(%{
      artifact: artifact,
      module: "wasm/" <> project.name,
      source_sha256: project.sha256,
      files: project.files |> Map.keys() |> Enum.sort(),
      input_bytes: project.bytes,
      build_bytes: byte_size(built.output),
      bundle_path: path
    })
  end

  ## -------------------------------------------------------------- the bundle store

  # One directory, the newest few bundles, and a name derived from the artifact id rather
  # than taken from it: the id is minted by `Wasm.Artifact` but it reaches this function
  # through a struct a caller handed back, so it is validated before it is joined to a path.
  defp retain(artifact, bundle, opts) do
    with {:ok, root} <- forged_root(opts),
         {:ok, name} <- bundle_name(artifact),
         :ok <- File.mkdir_p(root),
         :ok <- File.write(Path.join(root, name), bundle, [:binary]) do
      prune(root, name)
      {:ok, Path.join(root, name)}
    else
      {:error, reason} -> {:error, {:bundle_not_retained, describe(reason)}}
    end
  end

  defp bundle_name(%Wasm.Artifact{id: id}) when is_binary(id) do
    if Regex.match?(~r/\A[A-Za-z0-9_-]{1,64}\z/, id),
      do: {:ok, id <> Bundle.extension()},
      else: {:error, {:invalid_artifact_id, describe(id)}}
  end

  defp bundle_name(artifact), do: {:error, {:invalid_artifact, describe(artifact)}}

  # Never the one just written. Mtimes are whole seconds, so nine forges inside one second
  # sort arbitrarily among themselves, and the arbitrary one that got dropped could be the
  # bundle the deploy on the next line was about to read.
  defp prune(root, keep) do
    case File.ls(root) do
      {:ok, entries} ->
        entries
        |> Enum.filter(&(String.ends_with?(&1, Bundle.extension()) and &1 != keep))
        |> Enum.map(&{&1, mtime(Path.join(root, &1))})
        |> Enum.sort_by(&elem(&1, 1), :desc)
        |> Enum.drop(@forged_bundles - 1)
        |> Enum.each(fn {entry, _mtime} -> File.rm(Path.join(root, entry)) end)

      {:error, _unreadable} ->
        :ok
    end
  end

  defp mtime(path) do
    case File.stat(path, time: :posix) do
      {:ok, %File.Stat{mtime: mtime}} -> mtime
      {:error, _absent} -> 0
    end
  end

  defp read_bundle(artifact, opts) do
    with {:ok, root} <- forged_root(opts),
         {:ok, name} <- bundle_name(artifact),
         path = Path.join(root, name),
         {:ok, %File.Stat{type: :regular, size: size}} <- File.lstat(path),
         :ok <- bound_bundle(size),
         {:ok, bundle} <- File.read(path) do
      bound_to_artifact(bundle, artifact)
    else
      {:ok, %File.Stat{type: type}} -> {:error, {:forged_bundle_unreadable, type}}
      {:error, reason} -> {:error, {:forged_bundle_unreadable, describe(reason)}}
    end
  end

  defp bound_bundle(size) do
    if size > Bundle.max_bytes(), do: {:error, {:forged_bundle_unreadable, :too_large}}, else: :ok
  end

  # The file on disk is held to the artifact the caller named before a byte of it is staged.
  # It is this node's own output, but it is a file, and a file is what somebody else can
  # replace.
  defp bound_to_artifact(bundle, artifact) do
    case Bundle.decode(bundle) do
      {:ok, %{artifact: decoded}} ->
        if decoded.id == artifact.id and decoded.component_sha256 == artifact.component_sha256,
          do: {:ok, bundle},
          else: {:error, {:forged_bundle_mismatch, artifact.id}}

      {:error, reason} ->
        {:error, {:forged_bundle_unreadable, describe(reason)}}
    end
  end

  ## --------------------------------------------------------------------- staging

  # `Ouroboros.Wasm.Deploy` takes an upload id, because that is how bytes reach a node from
  # a client. A local caller has the same bytes and uses the same door: one staging area,
  # one consume-once rule, no second path into the signer.
  defp stage(bytes, opts) do
    chunk = Upload.max_chunk_bytes()

    bytes
    |> chunks(chunk)
    |> Enum.reduce_while({:ok, nil, 0}, fn {piece, final?}, {:ok, id, offset} ->
      case Upload.append(id, offset, piece, final?, staging_opts(opts)) do
        {:ok, %{upload: id}} -> {:cont, {:ok, id, offset + byte_size(piece)}}
        {:error, reason} -> {:halt, {:error, {:staging_failed, describe(reason)}}}
      end
    end)
    |> case do
      {:ok, id, _offset} -> {:ok, id}
      {:error, _reason} = error -> error
    end
  end

  defp chunks(bytes, size) do
    count = max(div(byte_size(bytes) - 1, size) + 1, 1)

    for index <- 0..(count - 1) do
      offset = index * size
      length = min(size, byte_size(bytes) - offset)
      {binary_part(bytes, offset, length), index == count - 1}
    end
  end

  ## ------------------------------------------------------------------ the toolchain

  defp require_cargo_home(opts) do
    case cargo_home(opts) do
      path when is_binary(path) and path != "" ->
        {:ok, path}

      _unset ->
        {:error,
         {:no_cargo_home,
          "this node has no data directory, so it has nowhere to keep the registry cache a " <>
            "forge builds from; name one with `config :ouroboros, :wasm_forge_cargo_home`"}}
    end
  end

  defp require_cargo(opts) do
    case cargo(opts) do
      path when is_binary(path) ->
        {:ok, path}

      nil ->
        {:error,
         {:no_cargo,
          "no cargo on this node's PATH. A forge runs where the effect lands; an operator " <>
            "who wants a dedicated builder puts the toolchain, the warmed cache and the " <>
            "grant on that node"}}
    end
  end

  defp cargo(opts) do
    case Keyword.get(opts, :cargo) || Application.get_env(:ouroboros, :wasm_forge_cargo) do
      path when is_binary(path) and path != "" -> path
      _unset -> Exec.which("cargo")
    end
  end

  @doc """
  The registry cache this node builds against: node-local, never the operator's own by default.

  `<data_dir>/wasm/cargo-home`, warmed by `make wasm-sdk-cache`. Neither `$CARGO_HOME` nor
  `~/.cargo` is consulted unless an operator names one, and the reason is a file: a cargo
  home carries `config.toml`, and `[build] rustc-wrapper` in it is a program cargo runs on
  every crate. A developer's `~/.cargo` is a directory a great many things write to; making
  it the default put all of them inside the build (D19).
  """
  @spec cargo_home(keyword()) :: Path.t() | nil
  def cargo_home(opts \\ []) do
    case Keyword.get(opts, :cargo_home) || Application.get_env(:ouroboros, :wasm_forge_cargo_home) do
      path when is_binary(path) and path != "" -> path
      _unset -> data_subdir("cargo-home")
    end
  end

  defp target_installed?(nil, _opts), do: false

  defp target_installed?(cargo, _opts) do
    sysroot = Path.join([Path.dirname(cargo), "..", "lib", "rustlib", @target])
    File.dir?(Path.expand(sysroot)) or rustup_target?()
  end

  defp rustup_target?() do
    case Exec.which("rustup") do
      nil ->
        false

      rustup ->
        case Exec.run(rustup, ["target", "list", "--installed"],
               timeout_ms: 15_000,
               max_bytes: 8 * 1024
             ) do
          {:ok, %{status: 0, output: output}} -> String.contains?(output, @target)
          _other -> false
        end
    end
  end

  # Every crate the SDK's lock names, as a `.crate` in the operator's warmed cache. Checked
  # before cargo is spawned so a cold cache is one sentence naming what is missing, rather
  # than a build that fails somewhere inside a resolver.
  # A map and not a tuple: this reaches `capabilities.preview`, which answers a JSON-RPC
  # client, and a tuple is a shape that gets all the way there and then cannot be encoded.
  defp cache_state(nil), do: %{state: :no_cargo_home, missing: [], missing_count: 0}

  defp cache_state(home) do
    case missing_crates(home) do
      [] -> :warm
      missing -> %{state: :cold, missing: Enum.take(missing, 8), missing_count: length(missing)}
    end
  end

  defp warm?(home) do
    case cache_state(home) do
      :warm ->
        :ok

      %{state: :no_cargo_home} ->
        {:error, {:no_cargo_home, "this node has no data directory to keep a cache in"}}

      %{missing: missing, missing_count: count} ->
        {:error,
         {:cold_registry_cache,
          %{
            cargo_home: home,
            missing: missing,
            missing_count: count,
            remedy:
              "run `make wasm-sdk-cache` (or `cargo fetch --locked` in tui/wasm/guest) on this node"
          }}}
    end
  end

  defp missing_crates(home) do
    for {name, version} <- locked_crates(),
        Path.wildcard(Path.join([home, "registry", "cache", "*", "#{name}-#{version}.crate"])) ==
          [],
        do: "#{name}-#{version}"
  end

  # Parsed from the embedded lock rather than listed by hand: a dependency the SDK adds is a
  # crate the cache has to hold, and a second list is a second place for that to be wrong.
  defp locked_crates do
    @canonical_lock
    |> String.split("\n\n")
    |> Enum.filter(&String.contains?(&1, "\nsource = \"registry+"))
    |> Enum.flat_map(fn segment ->
      with [_, name] <- Regex.run(~r/\nname = "([^"]+)"/, segment),
           [_, version] <- Regex.run(~r/\nversion = "([^"]+)"/, segment) do
        [{name, version}]
      else
        _unparsed -> []
      end
    end)
  end

  ## ---------------------------------------------------------------------- plumbing

  defp author(opts) do
    case Keyword.get(opts, :author) do
      author when is_binary(author) and author != "" -> {:ok, author}
      other -> {:error, {:invalid_author, describe(other)}}
    end
  end

  @doc "Where this node's checkout of the guest SDK is, or a named refusal."
  @spec sdk_root(keyword()) :: {:ok, Path.t()} | {:error, term()}
  def sdk_root(opts \\ []) do
    candidate =
      case Keyword.get(opts, :sdk_path) || Application.get_env(:ouroboros, :wasm_sdk_path) do
        path when is_binary(path) and path != "" -> path
        _unset -> @sdk_default
      end

    if File.regular?(Path.join(candidate, "Cargo.toml")),
      do: {:ok, Path.expand(candidate)},
      else: {:error, {:no_guest_sdk, candidate}}
  end

  defp scratch_root(opts) do
    case Keyword.get(opts, :scratch_root) || data_subdir("builds") do
      path when is_binary(path) and path != "" ->
        case File.mkdir_p(path) do
          :ok -> {:ok, path}
          {:error, reason} -> {:error, {:scratch_unwritable, path, reason}}
        end

      _unset ->
        {:error, :no_data_dir}
    end
  end

  defp forged_root(opts) do
    case Keyword.get(opts, :forged_root) || data_subdir("forged") do
      path when is_binary(path) and path != "" -> {:ok, path}
      _unset -> {:error, :no_data_dir}
    end
  end

  defp data_subdir(leaf) do
    case Application.get_env(:ouroboros, :data_dir) do
      dir when is_binary(dir) and dir != "" -> Path.join([dir, "wasm", leaf])
      _unset -> nil
    end
  end

  @doc """
  The wall-clock ceiling one build runs under, which is never more than five minutes.

  Two ceilings, and the smaller one wins. This one is the forge's, and it is the one that
  fires: `Ouroboros.Provider.Native.Exec` signals the sandboxed process group at it, so the
  build stops and the `after` that removes the scratch directory runs. The other belongs to
  whoever called — on the effect path `config :ouroboros, :effect_timeout` bounds the whole
  effect, and `Ouroboros.Agent.Effects.ForgeWasmCapability` therefore asks for a build budget
  strictly inside it, because the runner's own deadline is a `brutal_kill` that runs no
  cleanup and would leave a cargo tree, and a compiler, behind (docs/WASM.md D19).
  """
  @spec build_timeout(keyword()) :: pos_integer()
  def build_timeout(opts \\ []) do
    configured =
      case Keyword.get(opts, :timeout_ms) || Application.get_env(:ouroboros, :wasm_forge_timeout) do
        ms when is_integer(ms) and ms > 0 -> ms
        _unset -> @default_timeout_ms
      end

    min(configured, @max_timeout_ms)
  end

  defp pool(opts), do: Keyword.get(opts, :pool, Pool)

  defp sign_opts(opts),
    do:
      Keyword.take(opts, [:signing_service, :signing_node, :epoch_nodes, :epoch_opts]) ++
        upload_opts(opts)

  defp deploy_opts(opts),
    do:
      Keyword.take(opts, [:registry, :pool, :store_root, :trust_policy, :start?, :limits]) ++
        upload_opts(opts)

  defp upload_opts(opts) do
    case Keyword.get(opts, :upload_root) do
      root when is_binary(root) and root != "" -> [upload_root: root]
      _unset -> []
    end
  end

  # `Ouroboros.Wasm.Upload` names its option `:root`; the verbs that consume an upload name
  # theirs `:upload_root`. One directory, two spellings, converted in one place.
  defp staging_opts(opts) do
    case Keyword.get(opts, :upload_root) do
      root when is_binary(root) and root != "" -> [root: root]
      _unset -> []
    end
  end

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

  defp unique, do: Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
