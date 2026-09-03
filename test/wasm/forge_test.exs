defmodule Ouroboros.Wasm.ForgeTest do
  # Not async: the live half spawns cargo and the real helper as OS children, starts mesh
  # agents, and moves `:upgrade_trust_policy` and `:native_sandbox`, both of which every
  # other process on this node reads from application environment.
  use ExUnit.Case, async: false

  alias Ouroboros.Mesh
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Provider.Native.Sandbox.Bwrap
  alias Ouroboros.Provider.Native.Sandbox.Helper
  alias Ouroboros.Provider.Native.Sandbox.SandboxExec
  alias Ouroboros.Runtime.Capabilities
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Bundle
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

    # Red without `dependencies/1`'s `map_size(table) == 1`. `features`, `version` and `git`
    # each change what cargo resolves or how it builds, and the path is rewritten by this
    # module anyway, so one key is the honest shape of this dependency.
    test "a guest dependency carrying anything but a path is refused", context do
      for extra <- [~s(features = ["x"]), ~s(version = "0.1"), ~s(git = "https://example")] do
        files =
          manifest(fixture(), fn toml ->
            String.replace(
              toml,
              ~s(ouroboros-guest = { path = "../../tui/wasm/guest" }),
              ~s(ouroboros-guest = { path = "../../tui/wasm/guest", #{extra} })
            )
          end)

        assert {:error, {:invalid_guest_dependency, [_key]}} = validate(files, context)
      end
    end

    # The count is bounded twice, in the two places an input can arrive, and each one has a
    # test: this is the directory half, which refuses at the thirty-third entry rather than
    # after reading a repository into memory.
    test "thirty-three files in a directory are refused during the walk", context do
      directory = Path.join(context.tmp, "too-many")
      copy!(ForgeFixture.project_root(), directory)
      File.mkdir_p!(Path.join(directory, "src"))

      for index <- 1..29 do
        File.write!(Path.join([directory, "src", "module#{index}.rs"]), "// filler\n")
      end

      assert {:error, {:too_many_files, 33, 32}} = Forge.preview(%{dir: directory}, build?: false)
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
    # Red without `sandboxed/5`'s `:none` arm. A build is arbitrary code at build time, so a
    # node that cannot fence one does not run one.
    test "a node with no sandbox backend refuses to build at all", context do
      previous = Application.get_env(:ouroboros, :native_sandbox)
      Application.put_env(:ouroboros, :native_sandbox, :none)
      Sandbox.forget()
      on_exit(fn -> restore(:native_sandbox, previous) end)
      on_exit(&Sandbox.forget/0)

      assert {:ok, preview} = Forge.preview(%{files: fixture()}, forge_opts(context))
      assert preview.build.outcome == :failed
      assert preview.build.reason =~ "sandbox_unavailable"

      # `{:no_backend, detection}` and not the bare `:no_backend` `Sandbox.wrap/4` answers
      # with: this refusal is the one taken *before* a scratch directory is made or a wrap is
      # attempted, and the reason says which check made it.
      assert preview.build.reason =~ "{:no_backend,"
      assert preview.build.reason =~ "sandbox disabled"
    end

    # Red without `Sandbox.fences_reads?/1` and the arm that consults it. A backend that can
    # bound writes and not reads is half a sandbox, and half of this lane's claim.
    #
    # Since W17 the third backend can fence reads — but only a helper binary that says so.
    # The two mutations and what each reddens, corrected after a review found this comment
    # naming the wrong one: make `fences_reads?/1` answer `true` for `:ouro_sandbox` however
    # it was probed and *this* test reddens, because a stale helper starts claiming a fence
    # it has not got. Delete the `%{backend: :ouro_sandbox}` clause instead — so the map
    # falls through to the bare-atom `false` — and the sibling test below reddens, because a
    # current helper stops being allowed to forge at all.
    test "a helper that does not claim the read allow-set is refused rather than used",
         context do
      stale = %{
        backend: :ouro_sandbox,
        executable: "/nowhere",
        version: nil,
        notes: "",
        read_fence: false
      }

      refute Sandbox.fences_reads?(stale)
      # And a detection with no such key at all — a cache written by an older node, a map
      # somebody built by hand — is the same answer. This fails closed.
      refute Sandbox.fences_reads?(Map.delete(stale, :read_fence))
      # The bare backend name claims nothing: the capability is the binary's, not the name's.
      refute Sandbox.fences_reads?(:ouro_sandbox)

      assert {:error, {:sandbox_cannot_fence_reads, :ouro_sandbox, why}} =
               Forge.sandbox_policy("/nowhere/cargo", context.builds, context.tmp, "/sdk", stale)

      assert why =~ "read allow-set"

      # The other two answer by name, because neither is a binary this repository ships.
      assert Sandbox.fences_reads?(:sandbox_exec)
      assert Sandbox.fences_reads?(:bwrap)
    end

    # The other half of C11, and the reason W17 is not just a Rust change: a helper that
    # reports the feature is admitted, with the same builder policy the other two get.
    test "a helper that reports the read allow-set builds under the builder policy", context do
      current = %{
        backend: :ouro_sandbox,
        executable: "/nowhere",
        version: "0.1.0",
        notes: "",
        read_fence: true
      }

      assert Sandbox.fences_reads?(current)

      assert {:ok, policy} =
               Forge.sandbox_policy(
                 "/nowhere/cargo",
                 context.builds,
                 context.tmp,
                 "/sdk",
                 current
               )

      assert policy.mode == :builder
      assert policy.network == false
      assert "/sdk" in policy.readable
      # Canonical on both sides: `builder_policy/1` resolves the roots it names, and on this
      # Mac the temp directory reaches the test through a symlink (`/var` -> `/private/var`).
      # The forge already canonicalises its build directory for the same reason — a root in
      # the other spelling is a rule the kernel matches nothing against.
      assert Enum.sort(policy.writable) ==
               Enum.sort(Enum.map([context.builds, context.tmp], &canonical_root/1))

      # And the request that reaches the helper carries the allow-set — for this mode and
      # for no other. Red without `Helper.request/2`'s `readable` clause.
      request = Helper.request(Sandbox.with_scratch(policy, "/scratch"), %{root: context.builds})
      assert request["mode"] == "builder"
      assert request["readable"] == policy.readable
    end

    test "the builder policy denies the network, names its writable roots, and fences reads",
         context do
      policy =
        Sandbox.builder_policy(
          writable: [context.builds, context.tmp],
          readable: ["/a-toolchain-root"]
        )

      assert policy.mode == :builder
      assert policy.network == false
      assert policy.protected == []
      assert policy.protected_segments == []
      # Canonical on both sides: `builder_policy/1` resolves the roots it names, and on this
      # Mac the temp directory reaches the test through a symlink (`/var` -> `/private/var`).
      # The forge already canonicalises its build directory for the same reason — a root in
      # the other spelling is a rule the kernel matches nothing against.
      assert Enum.sort(policy.writable) ==
               Enum.sort(Enum.map([context.builds, context.tmp], &canonical_root/1))

      assert "/a-toolchain-root" in policy.readable

      # Every platform root is in it, and the profile is closed by default rather than
      # opening reads the way every other policy this module makes does.
      for root <- Sandbox.platform_readable(),
          do: assert(canonical_root(root) in policy.readable)

      profile = SandboxExec.profile(policy)
      assert profile =~ "(deny default)"
      refute profile =~ "\n(allow file-read*)\n"
      assert profile =~ "(allow file-read* (subpath (param \"OURO_READABLE_0\")))"
      assert profile =~ "(allow file-write* (subpath (param \"OURO_WRITABLE_0\")))"
      assert profile =~ "(deny network*)"
    end

    # The Linux half, as far as a pure function can be pinned: `/` is not bound at all, so
    # the roots below are the whole of what a build can see. Live behaviour is unverified and
    # docs/WASM.md D18 and §12 say so — this asserts the argv, not the kernel.
    test "the bubblewrap form of the builder policy binds only the roots it names" do
      policy =
        Sandbox.builder_policy(writable: ["/build"], readable: ["/toolchain"])
        |> Sandbox.with_scratch("/scratch")

      options = Bwrap.options(%{root: "/build"}, policy)

      refute Enum.chunk_every(options, 2, 1, :discard) |> Enum.any?(&(&1 == ["--ro-bind", "/"]))
      assert "--die-with-parent" in options
      assert "--unshare-net" in options
      assert "--tmpfs" in options
    end

    # The read set, as one list, because "what can a build read" should have one answer.
    test "the read set is the toolchain, the SDK and the world file — and nothing else" do
      {:ok, sdk} = Forge.sdk_root([])
      set = Forge.read_set("/opt/rust/bin/cargo", sdk)

      rustup = System.get_env("RUSTUP_HOME") || Path.expand("~/.rustup")

      assert "/opt/rust/bin" in set
      assert sdk in set
      assert Path.expand("../wit", sdk) in set
      assert rustup in set or Path.expand(rustup) in set
      assert length(set) == 4
    end

    # What the kernel actually enforces on this Mac, through the seam the real build uses:
    # `:cargo` names the program the forge wraps, so a script in its place runs behind
    # exactly the profile a `cargo build` runs behind.
    @tag @needs_build
    @tag timeout: 120_000
    test "on this node the fence denies a write outside the build directory and the network",
         context do
      outside = Path.join(context.tmp, "outside.txt")
      {:ok, sdk} = Forge.sdk_root([])
      readonly = Path.join(sdk, "PROBE-SHOULD-NOT-EXIST")
      on_exit(fn -> File.rm(readonly) end)
      probe = probe_script!(context, outside, readonly)

      assert {:ok, preview} =
               Forge.preview(%{files: fixture()}, Keyword.put(forge_opts(context), :cargo, probe))

      # The probe exits non-zero on purpose, so the forge reports the build as failed and
      # quotes what the kernel said.
      assert preview.build.outcome == :failed
      output = preview.build.output

      assert output =~ "inside-ok"
      assert output =~ "read-denied"
      assert output =~ "network-denied"

      # A write into a root the build may *read* is denied by both backends, and that is the
      # assertion worth making about a write: Seatbelt has no write rule for it, bubblewrap
      # bound it read-only.
      assert output =~ "ro-denied"
      refute File.exists?(readonly)

      # A write to a path outside the namespace altogether is where the two differ, and the
      # difference is mechanism rather than outcome. Seatbelt denies it: the path is there
      # and the profile says no. bubblewrap does not deny it — the host path is simply not
      # in the mount namespace, so the write lands in a throwaway tmpfs that dies with the
      # build. Both mean the same thing about the host, so that is what is asserted.
      refute File.exists?(outside)
    end

    # The HIGH the review found, now the other way round. This was a test asserting the
    # build *succeeded*; a component that `include_str!`s a planted secret was signed,
    # deployed and answered the secret through a mesh message. Red without the builder
    # policy — with the old `workspace_write` profile the compile succeeds.
    @tag @needs_build
    @tag timeout: 600_000
    test "a build cannot read a file outside the set, and the honest one still builds",
         context do
      secret = Path.join(context.tmp, "secret.txt")
      File.write!(secret, "CANARY-#{System.unique_integer([:positive])}")

      files =
        Map.update!(fixture(), "src/lib.rs", fn source ->
          source <> "\nconst _S: &str = include_str!(\"#{secret}\");\n"
        end)

      assert {:ok, preview} = Forge.preview(%{files: files}, forge_opts(context))
      assert preview.build.outcome == :failed
      assert preview.build.output =~ "secret.txt"
      assert preview.build.output =~ denial_pattern()

      # And the fence is a fence and not a broken toolchain: the same project without that
      # line builds under the same policy.
      assert {:ok, honest} = Forge.preview(%{files: fixture()}, forge_opts(context))
      assert honest.build.outcome == :ok
    end

    # `#[path]` reaches outside `src/` without an `include!` anywhere, which is why the fence
    # rather than the file allow-list is what has to stop it.
    @tag @needs_build
    @tag timeout: 600_000
    test "a module declared with #[path] outside the project cannot be read", context do
      File.mkdir_p!(context.builds)
      File.write!(Path.join(context.builds, "x.rs"), "pub fn hi() {}\n")

      files =
        fixture()
        |> Map.put("src/evil.rs", "#[path = \"../../x.rs\"]\npub mod x;\n")
        |> Map.update!("src/lib.rs", &(&1 <> "\nmod evil;\n"))

      assert {:ok, preview} = Forge.preview(%{files: files}, forge_opts(context))
      assert preview.build.outcome == :failed
      assert preview.build.output =~ "x.rs"
      assert preview.build.output =~ denial_pattern()

      # The companion its sibling has, and for the same reason: `Permission denied` on one
      # file proves a fence only beside a build that succeeds under the same policy. Without
      # this, a mode-000 file or a broken toolchain would pass the assertion above.
      assert {:ok, honest} = Forge.preview(%{files: fixture()}, forge_opts(context))
      assert honest.build.outcome == :ok
    end
  end

  ## ------------------------------------------------------------------ the ceiling

  describe "the wall-clock ceiling" do
    # Red without `Exec`'s own deadline being the one that fires: a build cut somewhere else
    # leaves the tree and the compiler behind it.
    @tag @needs_build
    @tag timeout: 300_000
    test "a build past its ceiling is a named refusal that leaves nothing running", context do
      assert {:ok, preview} =
               Forge.preview(
                 %{files: fixture()},
                 Keyword.put(forge_opts(context), :timeout_ms, 3_000)
               )

      assert preview.build.outcome == :failed
      assert preview.build.reason =~ "{:timeout, :deadline}"

      assert_settled(context)
    end

    test "five minutes is the ceiling, whatever a caller asks for" do
      assert Forge.build_timeout(timeout_ms: 3_000) == 3_000
      assert Forge.build_timeout(timeout_ms: 9_000_000) == 300_000
      assert Forge.build_timeout([]) == 300_000
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

    # Red without `cargo_home/1`'s node-local default. A `~/.cargo/config.toml` carrying
    # `[build] rustc-wrapper` is a program cargo runs on every crate, so whose directory this
    # is decides who runs code inside the build.
    test "the cache is the node's own, not the operator's, unless one is named", context do
      previous = Application.get_env(:ouroboros, :data_dir)
      Application.put_env(:ouroboros, :data_dir, context.tmp)
      on_exit(fn -> restore(:data_dir, previous) end)

      previous_home = Application.get_env(:ouroboros, :wasm_forge_cargo_home)
      Application.delete_env(:ouroboros, :wasm_forge_cargo_home)
      on_exit(fn -> restore(:wasm_forge_cargo_home, previous_home) end)

      # Restored, not deleted. Deleting it left every test that ran afterwards with no
      # `CARGO_HOME` at all, so `ForgeFixture.cargo_home/0` fell back to `~/.cargo` — warm on
      # a developer machine, and stone cold in the Linux container, where three later tests
      # failed for a reason that had nothing to do with them.
      ambient = System.get_env("CARGO_HOME")
      System.put_env("CARGO_HOME", "/an/ambient/cargo/home")

      on_exit(fn ->
        case ambient do
          nil -> System.delete_env("CARGO_HOME")
          value -> System.put_env("CARGO_HOME", value)
        end
      end)

      assert Forge.cargo_home([]) == Path.join([context.tmp, "wasm", "cargo-home"])
      assert Forge.cargo_home(cargo_home: "/named/by/an/operator") == "/named/by/an/operator"

      # Neither the ambient variable nor the developer's own directory is reachable by
      # default, which is the whole point of the default.
      refute Forge.cargo_home([]) =~ "ambient"
      refute Forge.cargo_home([]) == operator_cargo_home()
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

    # Red without `prune/2`'s `keep`. The eight planted bundles carry mtimes an hour in the
    # future, so the one this forge just wrote is the oldest file in the directory and is
    # exactly what a prune that did not know to keep it would drop — while a deploy was
    # about to read it.
    @tag @needs_build
    @tag timeout: 900_000
    test "pruning never drops the bundle the forge just wrote", context do
      live = live!(context)
      File.mkdir_p!(context.forged)
      future = System.os_time(:second) + 3_600

      for index <- 1..8 do
        path = Path.join(context.forged, "planted-#{index}.ouro-wasm")
        File.write!(path, "not a real bundle")
        File.touch!(path, future)
      end

      name = "prune-#{System.unique_integer([:positive])}"

      assert {:ok, forged} =
               Forge.forge(
                 %{files: ForgeFixture.counter(name)},
                 forge_opts(context, live, author: "prune-test")
               )

      assert File.regular?(forged.bundle_path)

      # Intact, and still the artifact it is filed under — which is what the deploy that
      # runs next would read.
      assert {:ok, %{artifact: decoded}} = Bundle.decode(File.read!(forged.bundle_path))
      assert decoded.id == forged.artifact_id

      bundles = context.forged |> File.ls!() |> Enum.filter(&String.ends_with?(&1, ".ouro-wasm"))
      assert length(bundles) == 8
      assert Path.basename(forged.bundle_path) in bundles
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

  # `/bin` is a symlink to `usr/bin` on Debian-family Linux, and `builder_policy/1`
  # canonicalises every root it names (a root that is a link is the thing it points at, to
  # Landlock and to Seatbelt alike). So the assertion is that each platform root is covered,
  # in whichever spelling names that directory.
  defp canonical_root(path) do
    case Ouroboros.Workspace.Path.canonicalize(path) do
      {:ok, canonical} -> canonical
      {:error, _absent} -> path
    end
  end

  defp fixture, do: ForgeFixture.project()

  defp operator_cargo_home, do: ForgeFixture.cargo_home()

  # A `bash` for the probe's network half: `/dev/tcp` is a bash feature and `sh` is dash on
  # Ubuntu. It is inside the read set on both platforms because the toolchain roots that hold
  # it are (`/bin` on macOS, `/usr` on Linux).
  defp bash!, do: System.find_executable("bash") || "/bin/bash"

  # The three backends refuse a read in three different words, and the difference is
  # mechanism rather than cosmetics. Seatbelt denies an open on a path that is there
  # (`EPERM`). bubblewrap never puts the file in the namespace, so the compiler is told it
  # is not there (`ENOENT`). `ouro-sandbox` stays in the host's own path namespace — a mount
  # can make a path read-only and cannot make it unreadable — so its read fence is Landlock
  # alone and arrives as `EACCES`. All three are the fence; only one is a permission error,
  # and one is not even an error about permission. The assertion beside this one — that the
  # honest fixture still builds under the same policy — is what makes any of the three mean
  # the fence rather than a broken toolchain.
  defp denial_pattern do
    case Sandbox.detect().backend do
      :sandbox_exec -> ~r/Operation not permitted/
      :ouro_sandbox -> ~r/Permission denied/
      _bwrap -> ~r/No such file or directory/
    end
  end

  # Nothing of this build may outlive its own refusal: no cargo or rustc still compiling in
  # the tree, and no tree. `pgrep -f` over the scratch root catches a survivor because every
  # rustc this build spawns carries an `--out-dir` beneath it.
  defp assert_settled(context) do
    {output, _status} =
      System.cmd("/usr/bin/pgrep", ["-f", context.builds], stderr_to_stdout: true)

    assert String.trim(output) == "",
           "a build process outlived its ceiling: #{inspect(output)}"

    leftovers =
      case File.ls(context.builds) do
        {:ok, entries} -> Enum.filter(entries, &String.starts_with?(&1, "forge-"))
        {:error, _absent} -> []
      end

    assert leftovers == [], "the build directory outlived its refusal: #{inspect(leftovers)}"
  end

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

    # The operator path takes every root from configuration, including the cache. Naming an
    # already-warm one here is what an operator does with `make wasm-sdk-cache`; the default
    # this overrides is `<data_dir>/wasm/cargo-home`, which has its own test.
    previous_home = Application.get_env(:ouroboros, :wasm_forge_cargo_home)
    Application.put_env(:ouroboros, :wasm_forge_cargo_home, operator_cargo_home())
    on_exit(fn -> restore(:wasm_forge_cargo_home, previous_home) end)

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
  # The probe lives in a directory of its own, and the file it tries to read in another.
  # `read_set/2` allows the *cargo executable's* directory — `process-exec` still has to read
  # the binary — so a probe sitting beside the file it is testing would be reading a
  # directory the fence is supposed to allow, and would prove nothing.
  defp probe_script!(context, outside, readonly) do
    directory = Path.join(context.tmp, "probe")
    File.mkdir_p!(directory)
    path = Path.join(directory, "probe.sh")

    unreadable = Path.join(context.tmp, "secrets/unreadable.txt")
    File.mkdir_p!(Path.dirname(unreadable))
    File.write!(unreadable, "not for a build")

    # Effects, not kernel prose. Seatbelt refuses a connect with EPERM and an unshared
    # network namespace refuses it with ENETUNREACH; `nc` is spelled differently on the two
    # platforms and its macOS `-G` is not an option elsewhere. What both backends agree on is
    # whether the connection happened, so the probe reports that and the test asserts it.
    File.write!(path, """
    #!/bin/sh
    if echo ok > ./inside.txt 2>/dev/null; then echo inside-ok; else echo inside-denied; fi
    if echo ok > #{outside} 2>/dev/null; then echo outside-ok; else echo outside-denied; fi
    if echo ok > #{readonly} 2>/dev/null; then echo ro-ok; else echo ro-denied; fi
    if cat #{unreadable} >/dev/null 2>&1; then echo read-ok; else echo read-denied; fi
    if #{bash!()} -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
      echo network-open
    else
      echo network-denied
    fi
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
      # An operator naming their own cache, which is the only way `~/.cargo` is ever used
      # (D19). The default is node-local and there is a test for that below.
      cargo_home: operator_cargo_home(),
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
  ## ------------------------------------------------------- W20: roles as a check

  # An `:erpc` that records the call instead of making it, so the *contents* of a forward can
  # be asserted rather than the fact that a remote node was unreachable. It runs in the calling
  # process, which is what lets a test read what was sent out of its own mailbox.
  #
  # `:answer` in the process dictionary is what it hands back; `:builder_opts`, when set, is
  # merged over the wire options and `forge_here/2` is then invoked **for real** on this node —
  # a loopback builder, with the builder's own configuration arriving where a real builder's
  # comes from (its own node) rather than off the wire.
  defmodule ForwardProbe do
    @moduledoc false

    def call(target, module, function, [input, opts] = args, timeout) do
      send(self(), {:forwarded, target, module, function, args, timeout})

      case {Process.get({__MODULE__, :answer}), Process.get({__MODULE__, :builder_opts})} do
        {nil, nil} -> {:ok, %{forwarded: true}}
        {nil, builder} -> apply(module, function, [input, Keyword.merge(opts, builder)])
        {answer, _builder} -> answer
      end
    end
  end

  describe "W20: where a forge runs is a check (D29, C14)" do
    # All thirty-six: three roles × four settings × three fleets, with the expectation written
    # out here rather than computed from the code under test. Red on the `:signer` clause, on
    # the `:no_builder_node` branch, on the `:builder`-builds-locally clause, on the lowest-name
    # ordering, and on the refusal of a setting that is neither word.
    test "placement/3 is the whole table" do
      core = :core@example
      signer = :signer@example
      later = :"m-builder@example"
      earlier = :"a-builder@example"

      fleets = [
        {:none, []},
        {:one_builder, [{core, :core}, {later, :builder}, {signer, :signer}]},
        {:two_builders,
         [{core, :core}, {later, :builder}, {signer, :signer}, {earlier, :builder}]}
      ]

      combinations =
        for role <- [:core, :builder, :signer],
            setting <- [:local, :builder, :buidler, nil],
            {shape, fleet} <- fleets,
            do: {role, setting, shape, fleet}

      assert length(combinations) == 36

      for {role, setting, shape, fleet} <- combinations do
        expected =
          cond do
            # A signer refuses under every setting and every fleet. This is C14's word
            # "unconditionally", written out.
            role == :signer -> :signer_node
            setting == :local -> :local
            setting != :builder -> :invalid_placement
            role == :builder -> :local
            shape == :none -> :no_builder_node
            shape == :one_builder -> {:forward, later}
            shape == :two_builders -> {:forward, earlier}
          end

        actual =
          case Forge.placement(role, setting, fleet) do
            :local -> :local
            {:forward, target} -> {:forward, target}
            {:refuse, {reason, why}} when is_binary(why) and why != "" -> reason
          end

        assert actual == expected,
               "placement(#{inspect(role)}, #{inspect(setting)}, #{shape}) was " <>
                 "#{inspect(actual)} and should be #{inspect(expected)}"
      end

      # And each refusal says which one it is, in words an operator can act on.
      assert {:refuse, {:signer_node, signer_why}} = Forge.placement(:signer, :local, [])
      assert signer_why =~ "signing key"
      assert {:refuse, {:no_builder_node, none}} = Forge.placement(:core, :builder, [])
      assert none =~ ":builder"
      assert {:refuse, {:invalid_placement, typo}} = Forge.placement(:core, :buidler, [])
      assert typo =~ ":local or :builder"
    end

    # Red without the `:signer` clause of `placement/3`, twice over: once through `forge/2`,
    # which is the path an effect and `capabilities.admit` take, and once through
    # `forge_here/2`, which is the entry point a *forwarded* forge lands on.
    #
    # And red without the check being **in front of** the input, which is the property the
    # first cut asserted nowhere: both inputs here are ones the forge would refuse on their own
    # merits — a directory that does not exist, and an inline project that violates C9 — so a
    # role check that ran after `collect/1` would answer the input's refusal instead of this
    # one. Moving the check behind collect+validate turns both of these red.
    test "a :signer refuses before the input is read at all", context do
      opts = forge_opts(context, nil, author: "server-owned-principal")
      absent = Path.join(context.tmp, "no-such-proposal")
      refute File.exists?(absent)

      # A C9 violation this suite already proves is caught: thirty-three files.
      oversized =
        Enum.reduce(1..29, fixture(), fn index, acc ->
          Map.put(acc, "src/module#{index}.rs", "// filler\n")
        end)

      assert {:error, {:too_many_files, 33, 32}} = Forge.forge(%{files: oversized}, opts)
      assert {:error, {:forge_input_unreadable, _}} = Forge.forge(%{dir: absent}, opts)

      with_role(:signer)

      for input <- [%{dir: absent}, %{files: oversized}, %{files: fixture()}] do
        assert {:error, {:forge_refused, :signer_node, why}} = Forge.forge(input, opts),
               "a :signer answered something other than its own refusal for #{inspect(Map.keys(input))}"

        assert why =~ "signing key"
        assert why =~ "D29"
      end

      assert {:error, {:forge_refused, :signer_node, _}} =
               Forge.forge_here(%{files: oversized}, opts)

      # Nothing on the way to saying so: no scratch root, no bundle directory, no tree at all.
      refute File.exists?(context.builds), "a refused forge created a scratch root"
      refute File.exists?(context.forged), "a refused forge created a bundle directory"
      assert File.ls!(context.tmp) == []
    end

    # The impure half, against the real `Ouroboros.Cluster.role/0` and this node's own
    # configuration rather than an argument a test chose.
    test "placement_here/1 reads this node's role and this node's setting" do
      assert Forge.placement_here() == :local

      previous = Application.get_env(:ouroboros, :wasm_forge_placement)
      Application.put_env(:ouroboros, :wasm_forge_placement, :builder)
      on_exit(fn -> restore(:wasm_forge_placement, previous) end)

      # This node is `:core` and no `:builder` is connected, which is exactly the refusal an
      # operator who set the key on a one-node fleet should get.
      assert {:refuse, {:no_builder_node, _}} = Forge.placement_here()

      with_role(:signer)
      assert {:refuse, {:signer_node, _}} = Forge.placement_here()
    end

    # H1. Red without the origin's own `collect/1` + `validate/2` in `forward/3`: a path is a
    # fact about *this* filesystem, and a builder handed one walks its own at that name —
    # `ENOENT` on a good day, and on a bad one whatever this other machine keeps there, built
    # and signed under the origin's principal. Its refusals are also a filesystem oracle for
    # whoever reached the origin.
    #
    # M2. Red without the allow-list: every path, process name and service in `opts` is a fact
    # about the origin, and D29's sentence is that everything the builder does is its own.
    test "a forward carries the validated project inline and nothing about this machine",
         context do
      builder = :"a-builder@example"
      project = Path.join(context.tmp, "proposal")
      File.mkdir_p!(project)

      for {path, contents} <- fixture() do
        target = Path.join(project, path)
        File.mkdir_p!(Path.dirname(target))
        File.write!(target, contents)
      end

      poisoned =
        forge_opts(context, nil,
          author: "server-owned-principal",
          name: "forge-fixture",
          eval: %{probes: [], budget_ms: 1_000, required: :all},
          start_config: "{}",
          placement: :builder,
          peers: [{:core@example, :core}, {builder, :builder}],
          rpc: ForwardProbe,
          timeout_ms: 60_000,
          # Every one of these would decide something on the builder if it travelled.
          signing_service: self(),
          signing_node: :signer@example,
          epoch_nodes: [:core@example],
          sdk_path: "/origin/sdk",
          pool: :origin_pool,
          trust_policy: [allow_unsigned: true]
        )

      # The probe answers with no bundle, so the forward is refused by name — which is itself
      # the right answer and is asserted on its own below. What this test reads is what was
      # *sent*.
      assert {:error, {:forge_forward_failed, ^builder, {:no_bundle, _}}} =
               Forge.forge(%{dir: project}, poisoned)

      assert_received {:forwarded, ^builder, Ouroboros.Wasm.Forge, :forge_here, [input, remote],
                       timeout}

      # The project, inline, exactly as this node collected and validated it — and never a
      # path, which is the whole of H1.
      assert input == %{files: fixture()}
      refute Map.has_key?(input, :dir)

      # The attrs, and only the attrs, plus the two deadlines.
      assert Enum.sort(Keyword.keys(remote)) ==
               [:author, :eval, :forge_deadline_ms, :name, :start_config, :timeout_ms]

      assert Keyword.fetch!(remote, :author) == "server-owned-principal"
      assert Keyword.fetch!(remote, :name) == "forge-fixture"
      assert Keyword.fetch!(remote, :eval) == Keyword.fetch!(poisoned, :eval)
      assert Keyword.fetch!(remote, :start_config) == "{}"

      # M1. Three deadlines, each strictly inside the next: cargo, then the builder's whole
      # forge, then what the origin waits — which is itself inside the effect runner's own, so
      # a brutal-kill never lands on a caller that is still owed an answer.
      assert Keyword.fetch!(remote, :timeout_ms) == 40_000
      assert Keyword.fetch!(remote, :forge_deadline_ms) == 50_000
      assert timeout == 60_000

      assert Keyword.fetch!(remote, :timeout_ms) < Keyword.fetch!(remote, :forge_deadline_ms)
      assert Keyword.fetch!(remote, :forge_deadline_ms) < timeout
    end

    # H1's other half. An input the origin's own C9 refuses never reaches the wire, so the
    # builder is never the thing that says no — and the oracle closes.
    test "a project this node refuses is refused here, and nothing is sent", context do
      opts =
        forge_opts(context, nil,
          author: "server-owned-principal",
          placement: :builder,
          peers: [{:"a-builder@example", :builder}],
          rpc: ForwardProbe
        )

      files = Map.put(fixture(), "src/../../escape.rs", "// no\n")
      assert {:error, {:path_escape, _path}} = Forge.forge(%{files: files}, opts)
      refute_received {:forwarded, _target, _module, _function, _args, _timeout}
    end

    # H1. The far end refuses a path by name rather than walking its own filesystem at it.
    test "forge_here refuses an input that names a directory", context do
      assert {:error, {:forge_refused, :path_over_the_wire, why}} =
               Forge.forge_here(%{dir: context.tmp}, author: "server-owned-principal")

      assert why =~ "origin's filesystem"
      refute File.exists?(context.builds)
    end

    # M2. A builder never forwards again, whatever the options say. The project is one C9
    # refuses, so this costs no build and still reaches the point where a re-dispatch would
    # have happened.
    test "forge_here never forwards, however its options are shaped", context do
      files = Map.put(fixture(), "src/../../escape.rs", "// no\n")

      assert {:error, {:path_escape, _path}} =
               Forge.forge_here(
                 %{files: files},
                 forge_opts(context, nil,
                   author: "server-owned-principal",
                   placement: :builder,
                   peers: [{:"a-builder@example", :builder}],
                   rpc: ForwardProbe
                 )
               )

      refute_received {:forwarded, _target, _module, _function, _args, _timeout}
    end

    # M1's second half. The builder bounds the **whole** forge, not only cargo, in a task it
    # can stop — and sweeps what the stop left behind, because `Task.shutdown/2` runs no
    # `after`. Driven with a cargo that sleeps and a deadline far inside its ceiling, which is
    # the shape of "the origin has stopped waiting and this node is still working".
    test "a forwarded forge that outlives its deadline is stopped and leaves no build behind",
         context do
      sleeper = Path.join(context.tmp, "sleepy-cargo")
      File.write!(sleeper, "#!/bin/sh\nsleep 30\n")
      File.chmod!(sleeper, 0o755)

      opts =
        forge_opts(context, nil,
          author: "server-owned-principal",
          cargo: sleeper,
          timeout_ms: 30_000,
          forge_deadline_ms: 300
        )

      assert {:error, {:forge_timeout, 300}} = Forge.forge_here(%{files: fixture()}, opts)

      # The tree the killed task could not remove for itself is gone.
      leftovers =
        case File.ls(context.builds) do
          {:ok, entries} -> Enum.filter(entries, &String.starts_with?(&1, "forge-"))
          {:error, _absent} -> []
        end

      assert leftovers == [], "a stopped forge left its build tree behind: #{inspect(leftovers)}"
    end

    # A build is expensive and a refusal is not, so an operator learns which node would do the
    # work from the cheap verb. Red without the `placement` field in `Forge.preview/2` or the
    # one `Ouroboros.Runtime.Capabilities` carries out of it.
    test "capabilities.preview reports the placement, and does not dry-build where it would not forge",
         context do
      workspace = proposal!(context, "counter-proposal")

      assert {:ok, preview} = Capabilities.preview(workspace, ".ouroboros/capabilities/Counter")
      assert preview.placement == %{decision: :local, node: node()}

      with_role(:signer)

      assert {:ok, refused} = Capabilities.preview(workspace, ".ouroboros/capabilities/Counter")
      assert %{decision: :refuse, reason: :signer_node, detail: detail} = refused.placement
      assert detail =~ "signing key"

      # C9 still answered — the proposal is as valid as it was a moment ago — but no build was
      # attempted, because a dry build on a signer is the very thing being refused.
      assert refused.lock == :sdk_lock
      assert refused.build == :not_placed_here
      assert is_binary(JSON.encode!(refused))
    end

    # H2 and M4, on a real build. `forge_here/2` runs for real through the rpc seam — one
    # cargo build, one real signature, one real `.ouro-wasm` — and what comes back is bytes.
    # Red without `dispose(:return, …)`: the bundle would sit in the *builder's* forged root
    # and `deploy/3` on the origin would answer `{:forged_bundle_unreadable, :enoent}`.
    # Red without `receive_forged/3`'s `retain/3`: the same.
    @tag @needs_build
    @tag timeout: 900_000
    test "a forwarded forge comes back as bytes, is verified here, and deploys from here",
         context do
      live = live!(context)
      name = "counter-forward-#{System.unique_integer([:positive])}"
      id = "wasm/" <> name
      on_exit(fn -> Mesh.stop_agent(id) end)

      builder_root = Path.join(context.tmp, "builder-forged")

      # The builder's own configuration, arriving where a real builder's comes from.
      Process.put(
        {ForwardProbe, :builder_opts},
        forge_opts(context, live, forged_root: builder_root)
      )

      on_exit(fn -> Process.delete({ForwardProbe, :builder_opts}) end)

      origin =
        forge_opts(context, live,
          author: "forge-test-agent",
          name: name,
          start_config: "{}",
          placement: :builder,
          peers: [{:"a-builder@example", :builder}],
          rpc: ForwardProbe
        )

      assert {:ok, forged} = Forge.forge(%{files: counter_files(name)}, origin)

      # The receipt is a local forge's in every respect an operator or an effect reads.
      assert forged.name == name
      assert forged.module == id
      assert forged.imports == ["log"]
      assert forged.signer == @signer
      assert forged.artifact.metadata.author == "forge-test-agent"

      # The bytes are here, in **this** node's forged root, and never in the reply the effect
      # surface projects.
      refute Map.has_key?(forged, :bundle)
      assert String.starts_with?(forged.bundle_path, context.forged)
      assert File.regular?(forged.bundle_path)

      # And the builder kept nothing: a builder accumulating other people's signed capabilities
      # on its own disk is a second copy nobody asked for.
      refute File.exists?(builder_root)

      # H2's actual claim: the receipt is deployable from the origin.
      assert {:ok, outcome} = Forge.deploy(forged.artifact, [node()], forge_opts(context, live))
      assert outcome.state == :live
      assert outcome.component_sha256 == forged.component_sha256
      assert {:ok, _agent} = Mesh.send_message("forge-forward", id, %{"add" => 2})
      assert %{"count" => 2} = state(id).last_answer

      assert {:ok, %{state: :rolled_back}} = Deploy.rollback(name, registry: live.registry)

      # M4. The same real bundle, replayed through a canned answer, against an origin that
      # asked for something else. A bundle is exactly what `Bundle.verify/2` exists for, and
      # the builder is the one node in this exchange whose output the origin did not produce.
      bundle = File.read!(forged.bundle_path)
      returned = forged |> Map.delete(:bundle_path) |> Map.put(:bundle, bundle)

      Process.delete({ForwardProbe, :builder_opts})
      Process.put({ForwardProbe, :answer}, {:ok, returned})
      on_exit(fn -> Process.delete({ForwardProbe, :answer}) end)

      # The author inside the signature is the principal, or the bundle is not the one that
      # was asked for. This is the check that makes a forwarded forge's provenance mean
      # anything at all: the origin never sees the component bytes before they are signed.
      assert {:error, {:forged_bundle_refused, _target, {:author_mismatch, _}}} =
               Forge.forge(
                 %{files: counter_files(name)},
                 Keyword.put(origin, :author, "somebody-else")
               )

      # And the capability it claims to be. A `:name` the *input* disagrees with never gets
      # this far — `declared_name/2` refuses it on the origin before a forward — so the case
      # this arm is for is the one an honest builder cannot produce: a well-formed, correctly
      # signed bundle for a different capability entirely, returned for this request.
      assert {:error, {:name_mismatch, _asked, ^name}} =
               Forge.forge(%{files: counter_files(name)}, Keyword.put(origin, :name, "elsewhere"))

      other = "another-capability"

      assert {:error, {:forged_bundle_refused, _target, {:name_mismatch, _, ^name}}} =
               Forge.forge(%{files: counter_files(other)}, Keyword.put(origin, :name, other))

      # And the signature, against this node's own trust policy.
      Process.put(
        {ForwardProbe, :answer},
        {:ok, Map.put(returned, :bundle, flip_last(bundle))}
      )

      assert {:error, {:forged_bundle_refused, _target, _reason}} =
               Forge.forge(%{files: counter_files(name)}, origin)

      # A builder that answers with no bundle at all is a forward that failed, by name.
      Process.put({ForwardProbe, :answer}, {:ok, Map.delete(returned, :bundle)})

      assert {:error, {:forge_forward_failed, _target, {:no_bundle, _}}} =
               Forge.forge(%{files: counter_files(name)}, origin)

      # And a refusal the builder made travels back as the builder's, not as this node's.
      Process.put({ForwardProbe, :answer}, {:error, {:no_cargo, "no cargo on that node"}})

      assert {:error, {:forge_refused_by, _target, {:no_cargo, _}}} =
               Forge.forge(%{files: counter_files(name)}, origin)
    end
  end

  # `boot_role!/0`'s own key, so the role a test sets is the role every reader sees —
  # `Ouroboros.Cluster.role/0` reads `:persistent_term` first and falls back to configuration
  # only where this runtime never started. Restored rather than erased: this VM booted with a
  # role and the suites after this one read it.
  defp with_role(role) do
    key = {Ouroboros.Cluster, :node_role}
    previous = :persistent_term.get(key, :absent)
    :persistent_term.put(key, role)

    on_exit(fn ->
      case previous do
        :absent -> :persistent_term.erase(key)
        restored -> :persistent_term.put(key, restored)
      end
    end)
  end

  # One byte of the component section, changed. Enough that the signature no longer covers
  # what is in the file.
  defp flip_last(binary) do
    at = byte_size(binary) - 1
    <<byte>> = binary_part(binary, at, 1)
    binary_part(binary, 0, at) <> <<Bitwise.bxor(byte, 1)>>
  end
end
