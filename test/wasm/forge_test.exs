defmodule Ouroboros.Wasm.ForgeTest do
  # Not async: the live half spawns cargo and the real helper as OS children, starts mesh
  # agents, and moves `:upgrade_trust_policy` and `:native_sandbox`, both of which every
  # other process on this node reads from application environment.
  use ExUnit.Case, async: false

  alias Ouroboros.Mesh
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Runtime.Capabilities
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Deploy
  alias Ouroboros.Wasm.Forge
  alias Ouroboros.Wasm.ForgeFixture
  alias Ouroboros.Wasm.Pool

  @moduletag :capture_log

  @signer "wasm-forge-test-key"

  @needs_build ForgeFixture.tag()

  setup_all do
    ForgeFixture.ensure!()
    :ok
  end

  setup do
    tmp = Path.join(System.tmp_dir!(), "ouro-wasm-forge-#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf(tmp) end)

    %{
      tmp: tmp,
      builds: Path.join(tmp, "builds"),
      forged: Path.join(tmp, "forged"),
      uploads: Path.join(tmp, "uploads"),
      store_root: Path.join(tmp, "store")
    }
  end

  ## ---------------------------------------------------------------------- C9

  describe "C9: what a forge input may be" do
    test "the fixture project is what the rest of this suite mutates", context do
      assert {:ok, preview} = validate(fixture(), context)

      assert preview.name == "forge-fixture"
      assert preview.files == ["Cargo.lock", "Cargo.toml", "README.md", "src/lib.rs"]
      assert preview.lock == :sdk_lock
      assert preview.build == :skipped
      assert String.match?(preview.source_sha256, ~r/\A[0-9a-f]{64}\z/)
    end

    # Red without the `map_size(files) > @max_files` arm of `bound/1`.
    test "thirty-three files are refused before anything is copied", context do
      files =
        Enum.reduce(1..29, fixture(), fn index, acc ->
          Map.put(acc, "src/module#{index}.rs", "// filler\n")
        end)

      assert map_size(files) == 33
      assert {:error, {:too_many_files, 33, 32}} = validate(files, context)
    end

    # Red without the `total > @max_total_bytes` arm of `bound/1`.
    test "one byte over a mebibyte is refused", context do
      files = fixture()
      slack = 1024 * 1024 + 1 - Enum.reduce(files, 0, fn {_p, c}, sum -> sum + byte_size(c) end)
      files = Map.put(files, "src/big.rs", String.duplicate("x", slack))

      assert {:error, {:input_too_large, size, 1_048_576}} = validate(files, context)
      assert size == 1_048_577
    end

    # Red without the `..` arm of `validate_path/2`.
    test "a path that climbs out of the project is refused", context do
      files = Map.put(fixture(), "src/../../escape.rs", "// nope\n")

      assert {:error, {:path_escape, _path}} = validate(files, context)
    end

    # Red without the `Path.type(path) != :relative` arm of `validate_path/2`.
    test "an absolute path is refused", context do
      files = Map.put(fixture(), "/etc/passwd", "// nope\n")

      assert {:error, {:absolute_path, _path}} = validate(files, context)
    end

    # Red without the `:symlink` arm of `walk_entry/5`. A directory input is the only shape
    # that can carry one, which is why this is the one refusal that needs a real directory.
    test "a symlink inside a project directory is refused, not followed", context do
      directory = Path.join(context.tmp, "symlinked")
      copy!(ForgeFixture.project_root(), directory)
      File.ln_s!("/etc/hosts", Path.join(directory, "src/hosts.rs"))

      assert {:error, {:symlink_refused, "src/hosts.rs"}} =
               Forge.preview(%{dir: directory}, build?: false)
    end

    # Red without the `build.rs` arm of `validate_path/2` — and `src/build.rs` is the case
    # that matters, because `src/**.rs` is otherwise a path the allow-list admits.
    test "a build script is refused by name, wherever it is", context do
      assert {:error, {:build_script_refused, "build.rs"}} =
               validate(Map.put(fixture(), "build.rs", "fn main() {}\n"), context)

      assert {:error, {:build_script_refused, "src/build.rs"}} =
               validate(Map.put(fixture(), "src/build.rs", "fn main() {}\n"), context)
    end

    # Red without `@package_keys`. The second half of the build-script rule: a file the
    # allow-list admits is only a build script if this key names it.
    test "the package key that would make a source file a build script is refused", context do
      files =
        manifest(fixture(), &String.replace(&1, "publish = false", ~s(build = "src/lib.rs")))

      assert {:error, {:manifest_key_not_allowed, "package", ["build"]}} =
               validate(files, context)
    end

    # Red without `known_sections/1`.
    test "a [patch] override is refused", context do
      files =
        manifest(fixture(), fn toml ->
          toml <> "\n[patch.crates-io]\nserde_json = { path = \"/tmp/mine\" }\n"
        end)

      assert {:error, {:manifest_section_not_allowed, ["patch.crates-io"]}} =
               validate(files, context)

      replaced = manifest(fixture(), &(&1 <> "\n[replace]\n"))
      assert {:error, {:manifest_section_not_allowed, ["replace"]}} = validate(replaced, context)
    end

    # Red without `dependencies/1`'s `map_size(deps) == 1`.
    test "a second dependency is refused", context do
      files =
        manifest(fixture(), fn toml ->
          String.replace(toml, "[dependencies]\n", "[dependencies]\nserde_json = \"1\"\n")
        end)

      assert {:error, {:dependency_not_allowed, ["serde_json"]}} = validate(files, context)
    end

    # Red without `compare/2`'s `rest == entries(@canonical_lock)`.
    test "a lock that differs from the SDK's by one byte is refused", context do
      files =
        Map.update!(fixture(), "Cargo.lock", fn lock ->
          String.replace(lock, "version = \"1.0.104\"", "version = \"1.0.105\"", global: false)
        end)

      assert byte_size(files["Cargo.lock"]) == byte_size(fixture()["Cargo.lock"])
      assert {:error, {:lock_not_the_sdk_lock, :dependencies}} = validate(files, context)
    end

    # Red without `compare/2`'s root-entry equality.
    test "a lock whose own entry claims another dependency is refused", context do
      files =
        Map.update!(fixture(), "Cargo.lock", fn lock ->
          String.replace(lock, " \"ouroboros-guest\",\n]", " \"ouroboros-guest\",\n \"libc\",\n]")
        end)

      assert {:error, {:lock_not_the_sdk_lock, {:root_entry, _entry}}} = validate(files, context)
    end

    # Red without `profile/1`.
    test "a release profile that is not the SDK's is refused", context do
      files = manifest(fixture(), &String.replace(&1, "lto = true", "lto = false"))
      assert {:error, {:profile_override_refused, _profile}} = validate(files, context)

      other = manifest(fixture(), &(&1 <> "\n[profile.dev]\nopt-level = 3\n"))
      assert {:error, {:manifest_section_not_allowed, ["profile.dev"]}} = validate(other, context)
    end

    # Red without `agreed?/2`. The scanner takes the last of two `edition` keys and is
    # perfectly happy; `Toml` refuses the document, and the disagreement is the refusal.
    test "a manifest the scanner and a real TOML parser read differently is refused", context do
      files =
        manifest(
          fixture(),
          &String.replace(&1, "edition = \"2021\"", "edition = \"2021\"\nedition = \"2021\"")
        )

      assert {:error, {:invalid_manifest, _reason}} = validate(files, context)
    end

    test "a project missing its lock, its manifest or its entry point is refused", context do
      for file <- ["Cargo.lock", "Cargo.toml", "src/lib.rs"] do
        assert {:error, {:missing_files, [^file]}} =
                 validate(Map.delete(fixture(), file), context)
      end
    end
  end

  ## ------------------------------------------------------------------ the sandbox

  describe "the sandbox is the third fence" do
    # Red without `sandboxed/2`'s `{:unsandboxed, reason}` arm. A build is arbitrary code at
    # build time, so a node that cannot fence one does not run one.
    test "a node with no sandbox backend refuses to build at all", context do
      previous = Application.get_env(:ouroboros, :native_sandbox)
      Application.put_env(:ouroboros, :native_sandbox, :none)
      on_exit(fn -> restore(:native_sandbox, previous) end)

      assert {:ok, preview} = Forge.preview(%{files: fixture()}, forge_opts(context))
      assert preview.build.outcome == :failed
      assert preview.build.reason =~ "sandbox_unavailable"

      # `{:no_backend, detection}` and not the bare `:no_backend` `Sandbox.wrap/4` answers
      # with: this refusal is the one taken *before* a scratch directory is made or a wrap is
      # attempted, and the reason says which check made it.
      assert preview.build.reason =~ "{:no_backend,"
      assert preview.build.reason =~ "sandbox disabled"
    end

    # Red without `fenceable/2`. `sandbox-exec`'s segment denies are the last rules in the
    # profile, so a writable root under one of them is denied whatever the allows said.
    test "a build root under a protected segment is refused rather than silently denied",
         context do
      root = Path.join([context.tmp, ".ouroboros", "builds"])

      assert {:ok, preview} =
               Forge.preview(
                 %{files: fixture()},
                 Keyword.put(forge_opts(context), :scratch_root, root)
               )

      assert preview.build.outcome == :failed
      assert preview.build.reason =~ "build_root_inside_protected_segment"
    end

    test "the policy the forge computes denies the network and names two writable roots",
         context do
      scope = %{
        sandbox_mode: :workspace_write,
        root: context.builds,
        roots: [Forge.toolchain().cargo_home]
      }

      assert {:sandboxed, _label, policy} = Sandbox.decision(scope, Sandbox.detect())
      assert policy.network == false

      assert Enum.sort(policy.writable) ==
               Enum.sort([context.builds, Forge.toolchain().cargo_home])

      assert ".git" in policy.protected_segments
    end

    # What the kernel actually enforces on this Mac, through the seam the real build uses:
    # `:cargo` names the program the forge wraps, so a script in its place runs behind
    # exactly the profile a `cargo build` runs behind.
    @tag @needs_build
    @tag timeout: 120_000
    test "on this Mac the fence denies a write outside the scratch directory and the network",
         context do
      outside = Path.join(context.tmp, "outside.txt")
      probe = probe_script!(context, outside)

      assert {:ok, preview} =
               Forge.preview(%{files: fixture()}, Keyword.put(forge_opts(context), :cargo, probe))

      # The probe exits non-zero on purpose, so the forge reports the build as failed and
      # quotes what the kernel said.
      assert preview.build.outcome == :failed
      output = preview.build.reason

      assert File.regular?("/usr/bin/nc"), "the network half of this probe needs /usr/bin/nc"

      assert output =~ "inside-ok"
      assert output =~ "outside-denied"
      # The kernel's own words, quoted back: Seatbelt denies a connect as EPERM, which is
      # what `Sandbox.violation/3` matches and what a closed loopback port is not.
      assert output =~ "Operation not permitted"
      refute File.exists?(outside)
    end

    # The limit, stated as a test rather than as a sentence: Seatbelt's profile allows reads
    # everywhere, so a compile-time `include_str!` of a readable path outside the project
    # succeeds. See docs/WASM.md D18 and §12 — the fence is on writes, the network and the
    # dependency set, and it is not on reads.
    @tag @needs_build
    @tag timeout: 600_000
    test "reads are not fenced, and this is the limit that says so", context do
      files =
        Map.update!(fixture(), "src/lib.rs", fn source ->
          source <>
            "\nconst _HOSTS: &str = include_str!(\"/etc/hosts\");\n"
        end)

      assert {:ok, preview} = Forge.preview(%{files: files}, forge_opts(context))
      assert preview.build.outcome == :ok
    end
  end

  ## ------------------------------------------------------------- the registry cache

  describe "the registry cache" do
    # Red without `warm?/1`. Timed, because the claim is not only that a cold cache is
    # refused but that the refusal costs nothing: `--offline` would also refuse, eventually,
    # after cargo had been spawned and had looked.
    test "a cold cache is a named refusal, not a fetch", context do
      cold = Path.join(context.tmp, "cold-cargo-home")
      File.mkdir_p!(cold)

      started = System.monotonic_time(:millisecond)

      assert {:ok, preview} =
               Forge.preview(
                 %{files: fixture()},
                 Keyword.put(forge_opts(context), :cargo_home, cold)
               )

      elapsed = System.monotonic_time(:millisecond) - started

      assert preview.build.outcome == :failed
      assert preview.build.reason =~ "cold_registry_cache"
      assert preview.build.reason =~ "make wasm-sdk-cache"
      assert preview.toolchain.cache != :warm

      assert elapsed < 2_000,
             "a cold cache took #{elapsed}ms, which is long enough to have asked a network"

      # This map is what `capabilities.preview` answers a JSON-RPC client with, and a cold
      # cache is the branch that carries the most structure. A tuple in it encodes nowhere.
      assert is_binary(JSON.encode!(preview))
    end

    test "the crates the cache must hold are read from the SDK's own lock" do
      lock = Forge.canonical_lock()

      assert is_binary(lock)
      assert lock =~ "name = \"wit-bindgen\""
      refute lock =~ "name = \"forge-fixture\""
    end

    # The fixture is the lock a scaffolded project resolves to, and the module pins every
    # submitted project to the SDK's. If those two ever disagree, every forge refuses.
    test "the fixture's lock is the SDK's lock plus its own entry" do
      canonical = Forge.canonical_lock()
      fixture_lock = fixture()["Cargo.lock"]

      entry = """
      [[package]]
      name = "forge-fixture"
      version = "0.1.0"
      dependencies = [
       "ouroboros-guest",
      ]
      """

      assert String.contains?(fixture_lock, String.trim_trailing(entry, "\n"))

      assert fixture_lock
             |> String.split("\n\n")
             |> Enum.reject(&String.starts_with?(&1, "[[package]]\nname = \"forge-fixture\""))
             |> Enum.join("\n\n") == canonical
    end
  end

  ## ------------------------------------------------------------------------ live

  describe "forging the counter example" do
    @tag @needs_build
    @tag timeout: 900_000
    test "source in, signed component out, deployed, messaged, rolled back", context do
      live = live!(context)
      name = "counter-#{System.unique_integer([:positive])}"
      id = "wasm/" <> name
      on_exit(fn -> Mesh.stop_agent(id) end)

      files = counter_files(name)

      assert {:ok, forged} =
               Forge.forge(
                 %{files: files},
                 forge_opts(context, live, author: "forge-test-agent", start_config: "{}")
               )

      # 1. The node read the imports off bytes it built itself, and they are the world's one
      #    import — not a list a caller declared.
      assert forged.imports == ["log"]
      assert forged.world == Wasm.world()
      assert forged.name == name
      assert forged.module == id
      assert forged.start_id == id
      assert forged.signer == @signer

      assert forged.component_sha256 ==
               Wasm.Artifact.digest(File.read!(forged.bundle_path) |> component_of(forged))

      assert %Wasm.Artifact{} = forged.artifact
      assert forged.artifact.metadata.author == "forge-test-agent"
      assert forged.artifact.metadata.source_sha256 == forged.source_sha256
      assert forged.artifact.metadata.language == "rust"

      # 2. Deploy the bundle this node wrote, verified against this node's own trust policy.
      assert {:ok, outcome} = Forge.deploy(forged.artifact, [node()], forge_opts(context, live))

      assert outcome.state == :live
      assert outcome.name == name
      assert outcome.module == id
      assert outcome.component_sha256 == forged.component_sha256

      # 3. It answers, and it is the counter.
      assert is_pid(Mesh.whereis(id))
      assert {:ok, _agent} = Mesh.send_message("forge-test", id, %{"add" => 3})
      assert %{"count" => 3} = state(id).last_answer

      # 4. Roll it back: the wrapper is gone, the entry says so, the bytes stay.
      assert {:ok, rolled} = Deploy.rollback(name, registry: live.registry)
      assert rolled.state == :rolled_back
      assert Mesh.whereis(id) == nil
    end

    # Red without `bound_to_artifact/2`. The bundle is a file, and a file is what somebody
    # else can replace between the forge that wrote it and the deploy that reads it.
    test "a bundle that is not the artifact it is filed under is refused", context do
      {:ok, artifact} =
        Wasm.Artifact.build("\0asm\x01\x00\x00\x00 not the bytes",
          name: "impostor",
          epoch: 41,
          author: "nobody",
          imports: []
        )

      File.mkdir_p!(context.forged)
      File.write!(Path.join(context.forged, artifact.id <> ".ouro-wasm"), "not a bundle at all")

      assert {:error, {:forged_bundle_unreadable, _reason}} =
               Forge.deploy(artifact, [node()], forged_root: context.forged)
    end

    test "a deploy naming no node at all is refused", context do
      {:ok, artifact} =
        Wasm.Artifact.build("\0asm\x01\x00\x00\x00 bytes",
          name: "nowhere",
          epoch: 41,
          author: "nobody",
          imports: []
        )

      assert {:error, {:invalid_deploy_request, _shape}} =
               Forge.deploy(artifact, [], forged_root: context.forged)
    end
  end

  ## ------------------------------------------------------------- the operator path

  describe "a workspace proposal that is a Cargo project" do
    test "is listed as lane W, under the name the register will call it", context do
      workspace = proposal!(context, "counter-proposal")

      assert {:ok, [summary]} = Capabilities.list(workspace)
      assert summary.lane == :wasm
      assert summary.module == "wasm/counter-proposal"
      assert summary.description == "Counts, and says so."
      assert summary.readable?
    end

    # Red without `declared_name/2`. Two names for one thing is how a proposal comes to be
    # described as one capability and deployed as another — and it is refused before the
    # build, because the name is not a build product.
    test "whose manifest names a different capability than its Cargo.toml is refused",
         context do
      workspace = proposal!(context, "counter-proposal", manifest_name: "something-else")

      assert {:error, {:name_mismatch, _declared, "counter-proposal"}} =
               Capabilities.preview(workspace, ".ouroboros/capabilities/Counter")
    end

    test "is held to the manifest keys its own lane has", context do
      workspace = proposal!(context, "counter-proposal", manifest_keys: %{"module" => "Nope"})

      assert {:error, {:unknown_manifest_keys, ["module"]}} =
               Capabilities.preview(workspace, ".ouroboros/capabilities/Counter")

      oversized =
        proposal!(context, "counter-proposal",
          start: %{"config" => String.duplicate("x", 16 * 1024 + 1)}
        )

      assert {:error, {:invalid_manifest_field, "start.config"}} =
               Capabilities.preview(oversized, ".ouroboros/capabilities/Counter")
    end

    @tag @needs_build
    @tag timeout: 900_000
    test "previews as C9 validation plus a dry build", context do
      workspace = proposal!(context, "counter-proposal")

      assert {:ok, preview} = Capabilities.preview(workspace, ".ouroboros/capabilities/Counter")

      assert preview.lane == :wasm
      assert preview.module == "wasm/counter-proposal"
      assert preview.lock == :sdk_lock
      assert preview.files == ["Cargo.lock", "Cargo.toml", "manifest.json", "src/lib.rs"]
      assert preview.toolchain.cache == :warm
      assert preview.build.outcome == :ok
      assert preview.build.size > 0
      assert is_binary(JSON.encode!(preview))

      # A preview is not a prepared deploy: nothing was signed, so there is no artifact and
      # no epoch was allocated.
      refute Map.has_key?(preview, :artifact_id)
      refute Map.has_key?(preview, :epoch)
    end

    # The whole operator path, on this node's own register and this node's own helper: the
    # gateway verb is `capabilities.admit` at `:operate` and this is what it reaches.
    @tag @needs_build
    @tag timeout: 900_000
    test "admits by forging, signing and deploying it", context do
      name = "counter-admit-#{System.unique_integer([:positive])}"
      workspace = proposal!(context, name, start: %{"config" => "{}"})
      signer!(context)
      on_exit(fn -> Mesh.stop_agent("wasm/" <> name) end)

      assert {:ok, admitted} =
               Capabilities.admit(workspace, ".ouroboros/capabilities/Counter",
                 author: "session:operator-test"
               )

      assert admitted.lane == :wasm
      assert admitted.module == "wasm/" <> name
      assert admitted.state == :live
      assert admitted.started.id == "wasm/" <> name

      assert is_pid(Mesh.whereis("wasm/" <> name))
      assert {:ok, _agent} = Mesh.send_message("operator-test", "wasm/" <> name, %{"add" => 5})
      assert %{"count" => 5} = state("wasm/" <> name).last_answer

      assert {:ok, rolled} = Deploy.rollback(name)
      assert rolled.state == :rolled_back
    end
  end

  describe "provenance" do
    test "a forge with no author is refused before a file is read" do
      assert {:error, {:invalid_author, _}} = Forge.forge(%{files: %{}}, [])
      assert {:error, {:invalid_author, _}} = Forge.forge(%{files: %{}}, author: "")
    end
  end

  ## --------------------------------------------------------------------- helpers

  defp validate(files, _context), do: Forge.preview(%{files: files}, build?: false)

  defp fixture, do: ForgeFixture.project()

  defp counter_files(name), do: ForgeFixture.counter(name)

  defp manifest(files, transform), do: Map.update!(files, "Cargo.toml", transform)

  # A workspace holding one lane-W proposal: the counter example beside the operator's own
  # `manifest.json`, which is the only file `Ouroboros.Runtime.Capabilities` reads itself.
  defp proposal!(context, name, opts \\ []) do
    # A real node has a data directory, and the operator path takes its build scratch from
    # there rather than from an option — which also puts the build root *inside* a protected
    # sandbox root, the nesting `SandboxExec`'s re-allow rule exists for (D7).
    previous = Application.get_env(:ouroboros, :data_dir)
    Application.put_env(:ouroboros, :data_dir, context.tmp)
    on_exit(fn -> restore(:data_dir, previous) end)

    workspace = Path.join(context.tmp, "workspace-#{System.unique_integer([:positive])}")
    directory = Path.join(workspace, ".ouroboros/capabilities/Counter")
    File.mkdir_p!(Path.join(directory, "src"))

    Enum.each(counter_files(name), fn {path, contents} ->
      File.write!(Path.join(directory, path), contents)
    end)

    manifest =
      %{
        "name" => Keyword.get(opts, :manifest_name, name),
        "description" => "Counts, and says so.",
        # Lane W requires one (D12): there is no build peer running the author's own tests
        # here, so the signed eval spec is the test story.
        "eval" => %{
          "probes" => [
            %{"input" => %{"add" => 1}, "expect" => "any_reply"},
            %{"input" => %{"add" => 1}, "expect" => ["state_matches", "messages_received", 2]}
          ],
          "budget_ms" => 10_000,
          "required" => "all"
        }
      }
      |> Map.merge(Keyword.get(opts, :manifest_keys, %{}))
      |> then(fn map ->
        case Keyword.get(opts, :start) do
          nil -> map
          start -> Map.put(map, "start", start)
        end
      end)

    File.write!(Path.join(directory, "manifest.json"), JSON.encode!(manifest))
    workspace
  end

  defp copy!(from, to) do
    File.mkdir_p!(to)

    from
    |> Path.join("**")
    |> Path.wildcard()
    |> Enum.filter(&File.regular?/1)
    |> Enum.each(fn path ->
      target = Path.join(to, Path.relative_to(path, from))
      File.mkdir_p!(Path.dirname(target))
      File.cp!(path, target)
    end)
  end

  # A stand-in for cargo that reports, in its own output, what the kernel let it do. It is
  # spawned by the same `Sandbox.wrap/4` the real build goes through, so what it proves is
  # the profile the forge computes and not a profile a test wrote.
  defp probe_script!(context, outside) do
    path = Path.join(context.tmp, "probe.sh")

    File.write!(path, """
    #!/bin/sh
    if echo ok > ./inside.txt 2>/dev/null; then echo inside-ok; else echo inside-denied; fi
    if echo ok > #{outside} 2>/dev/null; then echo outside-ok; else echo outside-denied; fi
    echo "network: $(/usr/bin/nc -z -G 2 1.1.1.1 443 2>&1)"
    exit 3
    """)

    File.chmod!(path, 0o755)
    path
  end

  defp forge_opts(context, live \\ nil, extra \\ []) do
    base = [
      scratch_root: context.builds,
      forged_root: context.forged,
      upload_root: context.uploads,
      build?: true
    ]

    live_opts =
      case live do
        nil ->
          []

        live ->
          [
            signing_service: live.service,
            trust_policy: live.trust_policy,
            registry: live.registry,
            store_root: context.store_root,
            pool: live.pool,
            eval: live.eval
          ]
      end

    base ++ live_opts ++ extra
  end

  # A signing service under the name `Ouroboros.Wasm.Deploy` looks for when nothing was
  # passed to it, which is the shape of a single-node operator setup: one machine that is
  # both `:core` and `:signer`.
  defp signer!(context) do
    key_path = Path.join(context.tmp, "operator-signer.key")
    File.write!(key_path, :crypto.strong_rand_bytes(32))
    File.chmod!(key_path, 0o600)

    service =
      start_supervised!(
        {Service,
         [
           key_path: key_path,
           signer_id: @signer,
           storage:
             {Jido.Storage.ETS,
              table: String.to_atom("wasm_forge_operator_#{System.unique_integer([:positive])}")}
         ]}
      )

    {:ok, %{public_key: public}} = Service.public_info(service)

    previous = Application.get_env(:ouroboros, :upgrade_trust_policy)

    Application.put_env(:ouroboros, :upgrade_trust_policy,
      allow_unsigned: false,
      trusted_signers: %{@signer => public}
    )

    on_exit(fn -> restore(:upgrade_trust_policy, previous) end)

    signing_node = Application.get_env(:ouroboros, :signing_node)
    Application.delete_env(:ouroboros, :signing_node)
    on_exit(fn -> restore(:signing_node, signing_node) end)

    service
  end

  # The signer, the trust policy, the register and the helper pool a live forge needs, in the
  # shape `test/wasm/deploy_test.exs` already establishes them.
  defp live!(_context) do
    tmp = Path.join(System.tmp_dir!(), "ouro-forge-live-#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf(tmp) end)

    key_path = Path.join(tmp, "signer.key")
    File.write!(key_path, :crypto.strong_rand_bytes(32))
    File.chmod!(key_path, 0o600)

    service =
      start_supervised!(
        {Service,
         [
           name: nil,
           key_path: key_path,
           signer_id: @signer,
           storage:
             {Jido.Storage.ETS,
              table: String.to_atom("wasm_forge_journal_#{System.unique_integer([:positive])}")}
         ]},
        id: {Service, System.unique_integer([:positive])}
      )

    {:ok, %{public_key: public}} = Service.public_info(service)
    trust_policy = [allow_unsigned: false, trusted_signers: %{@signer => public}]

    previous = Application.get_env(:ouroboros, :upgrade_trust_policy)
    Application.put_env(:ouroboros, :upgrade_trust_policy, trust_policy)
    on_exit(fn -> restore(:upgrade_trust_policy, previous) end)

    signing_node = Application.get_env(:ouroboros, :signing_node)
    Application.delete_env(:ouroboros, :signing_node)
    on_exit(fn -> restore(:signing_node, signing_node) end)

    registry_name = String.to_atom("wasm_forge_registry_#{System.unique_integer([:positive])}")

    {:ok, registry} =
      Registry.start_link(
        name: registry_name,
        storage:
          {Jido.Storage.ETS,
           table: String.to_atom("wasm_forge_rollouts_#{System.unique_integer([:positive])}")}
      )

    on_exit(fn ->
      try do
        GenServer.stop(registry)
      catch
        :exit, _reason -> :ok
      end
    end)

    pool_name = :"wasm_forge_pool_#{System.unique_integer([:positive])}"
    {:ok, pool} = Pool.start(name: pool_name, handshake_timeout_ms: 15_000)

    on_exit(fn ->
      if Process.alive?(pool) do
        try do
          GenServer.stop(pool, :normal, 5_000)
        catch
          :exit, _reason -> :ok
        end
      end
    end)

    %{
      service: service,
      trust_policy: trust_policy,
      registry: registry_name,
      pool: pool,
      eval: %{
        probes: [
          %{input: %{"add" => 1}, expect: :any_reply},
          %{input: %{"add" => 1}, expect: {:state_matches, :messages_received, 2}}
        ],
        budget_ms: 10_000,
        required: :all
      }
    }
  end

  defp component_of(bundle, forged),
    do: binary_part(bundle, byte_size(bundle) - forged.size, forged.size)

  defp state(agent_id) do
    {:ok, server_state} = Mesh.state(agent_id)
    server_state.agent.state
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
