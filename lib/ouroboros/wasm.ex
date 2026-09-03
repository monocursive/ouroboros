defmodule Ouroboros.Wasm do
  @moduledoc """
  Lane W's entry point: where the `ouro-wasm` helper is, and the bounds this node speaks to
  it under.

  The helper is the containment boundary (docs/WASM.md §7.3). It is an isolated workspace
  member carrying a whole wasmtime, built by `make wasm` into `priv/wasm/` and fanned out to
  `_build/*/lib/ouroboros/priv/wasm/`. Nothing here builds it and nothing here requires it:
  **presence on disk is the operator opt-in**, exactly as it is for the Computer Use helper
  (`Ouroboros.Provider.Native.Desktop.helper_path/0`), and absence is an error tuple rather
  than a raise so a node that never built one boots and runs unchanged.

  Resolution order, same shape as the desktop helper's:

    1. `OUROBOROS_WASM_HELPER` — an absolute path to an operator build;
    2. a configured absolute `helper_path` under `config :ouroboros, :wasm`;
    3. the first existing candidate: the application's `priv/` (which is the `_build`
       fan-out `make wasm` writes), or a sibling of `ouro` itself.

  **Nothing in that order is derived from the working directory** (F1). The helper *is* the
  containment boundary, so the set of paths that may supply it has to be a property of the
  installation and never of where the daemon happens to have been started: a walk up the
  cwd's ancestors for `priv/wasm/ouro-wasm` meant any repository a user cloned and any
  directory an agent could write could hand this node the binary it spawns to contain
  untrusted code. A checkout that wants its own build says so with `OUROBOROS_WASM_HELPER`
  or with the `_build` fan-out `make wasm` already writes; a worktree that wants one says so
  with the env override or its own `priv/wasm/`.

  Settings are bounds on somebody else's program, so a malformed value falls back to the
  default rather than widening anything — the `Ouroboros.Provider.Native.Desktop.config/1`
  posture, for the same reason.
  """

  @helper "ouro-wasm"

  # The last `helper_readable` value warned about, so a misconfigured node logs once rather
  # than once per load. One term, replaced rather than grown.
  @warned_key {__MODULE__, :helper_readable_warned}

  # The world this node speaks. It is not configurable: admitting a component against a
  # world this build does not implement is exactly the lie the linker exists to prevent
  # (docs/WASM.md D5), so the handshake compares against this constant and nothing else.
  @world "ouroboros:capability@0.1.0"

  # W15. The second world the helper speaks (docs/WASM.md §8.2, D21). A different package, not
  # a wider capability: the two declare the same single import and differ in one export, and a
  # component admitted to one is not admitted to the other. Which of them a set of bytes is
  # ever offered as is the *signed manifest's* `kind`, not a caller's preference.
  @policy_world "ouroboros:policy@0.1.0"

  @defaults [
    helper_path: :bundled,
    # A `doctor` answer needs no wasm work at all, so a helper that cannot produce one
    # within this window is not slow, it is wrong.
    handshake_timeout_ms: 5_000,
    # Everything that is not `call`/`instantiate`: `doctor`, `inspect`, `load`, `drop`.
    # Sized by `load`, which compiles a component — the helper accepts up to 64 MiB of
    # them — rather than by `drop`, which is a map delete.
    request_timeout_ms: 30_000,
    # Added to a request's own `limits.deadline_ms` to get the transport's deadline for
    # `call` and `instantiate`. The guest's bound is the helper's epoch deadline; this is
    # headroom for the work around it — compiling, linking, lifting the reply out of guest
    # memory, and the trip back up the pipe.
    call_margin_ms: 10_000,
    # The helper's own read-bounded frame cap (`tui/wasm/src/main.rs`), matched here so a
    # frame this node would refuse is one the helper would never have sent.
    max_frame_bytes: 8 * 1024 * 1024,
    # How long a broken helper is left alone before a request may reconnect it. The same
    # window `Ouroboros.Provider.Native.Desktop.Pool` uses, for the same reason.
    broken_ms: 15_000,
    # What `Ouroboros.Wasm.Store` will hold before pruning evicts unreferenced bytes.
    # Eight components at the helper's 64 MiB per-component ceiling: far more than a
    # realistic corpus of capabilities, and still a number an operator would notice.
    store_budget_bytes: 512 * 1024 * 1024,
    # The bounds `Ouroboros.Wasm.Capability` stands an instance up under when its own
    # `initial_state` does not name them. Conservative on purpose: a capability that needs
    # more says so in the state it is deployed with, where the number is visible to whoever
    # signs it, rather than inheriting a generous node-wide default it never declared.
    #
    # Declared whole, and validated whole (see `valid?/2`): all three or none. A half-stated
    # bound is not a bound, and the helper refuses a request that omits one for the same
    # reason — "there is no unlimited default" is its sentence.
    capability_limits: [
      # About a tenth of a second of guest computation on this hardware, and three orders of
      # magnitude above what a JSON step function costs.
      fuel: 100_000_000,
      memory_bytes: 64 * 1024 * 1024,
      deadline_ms: 5_000
    ],
    # The **ceiling** the bounds above may be raised to, per capability, by the state a
    # capability is deployed with. `capability_limits` is the default; this is the most any
    # declaration can ask for, and `Ouroboros.Wasm.Capability.limits/1` clamps element-wise
    # against it (F3).
    #
    # It exists because `:limits` arrives in `initial_state`, `Ouroboros.Mesh.start_agent/2`
    # is remote-reachable, and Jido does not validate `initial_state` against the agent's
    # schema — so before this, a remote starter simply wrote the helper's own maxima into the
    # state it started a capability with and got them: a full trillion units of fuel, a
    # gibibyte, and sixty seconds of wall clock per message, on a node that had never agreed
    # to any of it. A ceiling is the only place that decision can honestly live, because it
    # is the node's and not the deployment's.
    #
    # Conservative on purpose, and still two orders of magnitude above the default: a
    # hundredth of the helper's fuel ceiling, a quarter of its memory ceiling, half its
    # deadline. Declared whole and validated whole, exactly as `capability_limits` is.
    capability_limits_max: [
      fuel: 10_000_000_000,
      memory_bytes: 256 * 1024 * 1024,
      deadline_ms: 30_000
    ],
    # Whether a capability's `initial_state` may name the directory its component bytes are
    # read from. Default **false**, and true only in this repository's test environment.
    #
    # `:store_root` is a test seam — it lets one agent read its own directory without touching
    # anything global — and on a remote-reachable start surface a test seam is an arbitrary
    # read: a starter that names a root runs whatever unsigned, unregistered bytes sit at
    # `<root>/wasm/components/sha256-<hex>.wasm` for any directory the BEAM user can read.
    # With this false the node's own store root is used whatever the state says (F3).
    allow_store_root_override: false,
    # W8. Whether this node will `Component::deserialize` an artifact its signer compiled.
    #
    # Default **true**, and the trade is written down rather than assumed (docs/WASM.md D24,
    # §12): the precompiled form turns a `load` from a compile into a mapping, and what it
    # costs is that a signer this node trusts can now hand it machine code instead of a
    # component — bytes wasmtime does not validate, running with the helper's own authority
    # rather than inside the guest's fence. Every containment bound in §7.3 is a bound on a
    # *component*, and an artifact skips all of them. The signature is the whole of the
    # boundary, which it always was for *what* a node runs and is now also for *how*.
    #
    # `false` refuses the fast form fleet-wide, everywhere at once, with no redeploy and no
    # resigning: every node compiles the source under §7.3's bounds exactly as it did before
    # W8. It is the switch an operator reaches for when a signing key's custody is in doubt.
    accept_precompiled: true,
    # W16, D25. Whether this node will run the helper without an OS sandbox around it.
    #
    # Default **`:required`**, and the asymmetry is the point: `:off` is a thing an operator
    # states, and every other outcome — no backend on this node, a backend that cannot fence
    # reads (`Ouroboros.Provider.Native.Sandbox.fences_reads?/1`), no data directory to put a
    # scratch in — is a **refusal to spawn**, not a quieter posture. A node with no fence is a
    # node that does not run wasm, rather than one that runs it a little less safely: the
    # helper maps machine code a signer produced (D24), and the sandbox is the wall that
    # bounds what a compromised artifact reaches once it is inside that process.
    #
    # `:off` spawns the helper plain, says so in `wasm.status` and logs one line per spawn.
    # It is for a node whose platform this runtime cannot sandbox and whose operator has read
    # D25 and decided the trade — never a fallback this code takes on its own.
    helper_sandbox: :required,
    # W16. Roots this node's helper may read **beyond** its own binary's directory, the
    # platform's toolchain roots, this node's component store and the forge's build directory.
    #
    # Empty on a node that has not said otherwise, because the default answer is the whole
    # fence: a helper reads component bytes out of this node's store and nothing else. It
    # exists because `Ouroboros.Wasm.Store.root/1` takes a `:root` and
    # `allow_store_root_override` can let a deployment name one, and a node that puts its
    # components somewhere else has to say where or its own loads are refused — by this pool,
    # before the helper, and then by the kernel.
    #
    # It widens a fence, so `helper_readable/0` vets it whole rather than trusting it: see the
    # rules there. `["/"]` was accepted before that vetting existed and took both walls away
    # at once.
    helper_readable: []
  ]

  @timeout_keys [:handshake_timeout_ms, :request_timeout_ms, :call_margin_ms, :broken_ms]
  @byte_keys [:max_frame_bytes, :store_budget_bytes]
  @limit_keys [:fuel, :memory_bytes, :deadline_ms]
  @limits_keys [:capability_limits, :capability_limits_max]

  @doc """
  The default instance bounds, as the map `Ouroboros.Wasm.Pool.instantiate/5` takes.

  `Ouroboros.Wasm.Capability` uses these when the state it was deployed with names none of
  its own. They are a floor an operator may raise, never a ceiling this build invents per
  request: the three bounds are always sent explicitly.
  """
  @spec capability_limits() :: %{
          fuel: pos_integer(),
          memory_bytes: pos_integer(),
          deadline_ms: pos_integer()
        }
  def capability_limits, do: Map.new(config(:capability_limits))

  @doc """
  The ceiling a deployed capability's own `:limits` may reach.

  `Ouroboros.Wasm.Capability.limits/1` clamps element-wise against this, so a declaration
  that asks for more runs under this instead and says so in the agent's `:error`. Read from
  `config :ouroboros, :wasm, :capability_limits_max`, whole or not at all.
  """
  @spec capability_limits_max() :: %{
          fuel: pos_integer(),
          memory_bytes: pos_integer(),
          deadline_ms: pos_integer()
        }
  def capability_limits_max, do: Map.new(config(:capability_limits_max))

  @doc """
  Whether a capability's `initial_state` may name its own component store root.

  False on any node that has not deliberately said otherwise, because the key arrives on a
  remote-reachable start surface and naming a root is naming which bytes run.
  """
  @spec allow_store_root_override?() :: boolean()
  def allow_store_root_override?, do: config(:allow_store_root_override) == true

  @doc """
  Whether this node will map a precompiled artifact at all (W8, D24).

  `true` unless an operator said otherwise, and a malformed value reads as the default the way
  every other setting here does. `false` makes `Ouroboros.Wasm.Store.form/4` answer the source
  form for every component on this node whatever its manifest declares — which every node can
  always compile — and is the one switch that takes the deserialize path away fleet-wide
  without resigning anything.
  """
  @spec accept_precompiled?() :: boolean()
  def accept_precompiled?, do: config(:accept_precompiled) == true

  @doc """
  Whether this node insists on an OS sandbox around its helper (W16, D25).

  `:required` unless an operator wrote `:off`, and a malformed value reads as `:required`
  the way every other setting here falls back to its default — which here means the safe
  direction, because the fallback for a posture setting must never be the weaker posture.
  """
  @spec helper_sandbox() :: :required | :off
  def helper_sandbox, do: config(:helper_sandbox)

  @doc """
  Extra roots this node's helper may read, **vetted**, or `[]` (W16, D25).

  A widening knob is the one setting that cannot fall back quietly to whatever it was given,
  so every entry has to survive four rules: it is an absolute path; it resolves to a directory
  that exists; it is not `/` and does not resolve to `/`; and it is not the node's data
  directory nor an ancestor of it. The last two are the ones that matter — `["/"]` was
  accepted before this existed and removed both of W16's walls in one line, and `["$HOME"]`
  or `[<data_dir>]` hands the helper the signing journal, the grants and the effect ledger.

  One offending entry rejects the **whole list**, with a warning naming it. A list an operator
  believes they wrote is not one this node silently prunes to the half it liked: a fence with
  three roots where four were configured is a fence nobody can reason about, and `[]` is the
  posture the node has when nothing is configured at all. The warning is logged once per
  distinct offending value rather than on every load.

  `Ouroboros.Wasm.Pool.status/1` reports the effective list, so what the fence actually is can
  be read off the node rather than inferred from configuration.
  """
  @spec helper_readable() :: [String.t()]
  def helper_readable do
    case config(:helper_readable) do
      [] -> []
      roots -> vetted(roots)
    end
  end

  defp vetted(roots) do
    case Enum.find_value(roots, fn root ->
           case unusable_root(root) do
             nil -> nil
             why -> {root, why}
           end
         end) do
      nil ->
        roots

      {root, why} ->
        warn_once(roots, root, why)
        []
    end
  end

  defp unusable_root(root) when not is_binary(root), do: :not_a_path
  defp unusable_root(""), do: :not_a_path
  defp unusable_root("/"), do: :the_whole_filesystem

  defp unusable_root(root) do
    if Path.type(root) == :absolute do
      resolved_root(root)
    else
      :not_an_absolute_path
    end
  end

  defp resolved_root(root) do
    case Ouroboros.Workspace.Path.canonicalize(root) do
      {:ok, "/"} -> :the_whole_filesystem
      {:ok, canonical} -> covers_data_dir(canonical)
      {:error, reason} -> {:not_a_directory_that_exists, reason}
    end
  end

  # `within?(data_dir, root)` is "the data directory is inside this root", which is exactly
  # what an ancestor is — and equality counts, because naming `<data_dir>` itself hands the
  # helper the signing journal, the grants, the permissions and the effect ledger, which are
  # the files the store root was narrowed away from in the first place.
  defp covers_data_dir(canonical) do
    case Application.get_env(:ouroboros, :data_dir) do
      dir when is_binary(dir) and dir != "" ->
        data_dir =
          case Ouroboros.Workspace.Path.canonicalize(dir) do
            {:ok, resolved} -> resolved
            {:error, _absent} -> Path.expand(dir)
          end

        if Ouroboros.Workspace.Path.within?(data_dir, canonical),
          do: :ancestor_of_the_data_directory

      _unset ->
        nil
    end
  end

  # Once per distinct configured value: this is read on the way to every load, and a node
  # whose configuration is wrong should say so rather than say so ten thousand times.
  defp warn_once(roots, root, why) do
    if :persistent_term.get(@warned_key, :none) != roots do
      :persistent_term.put(@warned_key, roots)

      require Logger

      Logger.warning(
        "config :ouroboros, :wasm, helper_readable: refused whole list — " <>
          "#{inspect(root)} is #{inspect(why)}; the helper reads only this node's own roots " <>
          "(docs/WASM.md D25)"
      )
    end

    :ok
  end

  @doc """
  This node's lane-W subtree, `<data_dir>/wasm`, or `nil` where there is no data directory.

  Where the pool puts a child's scratch and where the forge builds. It is deliberately **not**
  a readable root: `Ouroboros.Wasm.Pool` names the component store and the forge's build
  directory below it and nothing else, because this subtree also holds the upload staging
  area, the sign scratch, the forged bundles and the forge's cargo home — and a cargo home's
  `config.toml` on a builder node can name a `rustc-wrapper` and hold a registry credential.
  """
  @spec data_root() :: String.t() | nil
  def data_root do
    case Application.get_env(:ouroboros, :data_dir) do
      dir when is_binary(dir) and dir != "" -> Path.join(dir, "wasm")
      _unset -> nil
    end
  end

  @doc """
  Where `Ouroboros.Wasm.Forge` builds, `<data_dir>/wasm/builds`, or `nil`.

  Named here because the pool has to make it readable: the forge reads the import list off the
  product it just built with `Ouroboros.Wasm.Pool.inspect/2` (docs/WASM.md D18), and that path
  is a build directory rather than a store entry. Mirrors `Forge`'s own default; a forge told
  to build somewhere else says so to the pool as well.
  """
  @spec builds_root() :: String.t() | nil
  def builds_root do
    case data_root() do
      dir when is_binary(dir) -> Path.join(dir, "builds")
      nil -> nil
    end
  end

  @doc "The world id this node admits a capability component against."
  @spec world() :: String.t()
  def world, do: @world

  @doc "The world id this node admits a policy component against (W15)."
  @spec policy_world() :: String.t()
  def policy_world, do: @policy_world

  @doc """
  The two kinds a signed lane-W manifest may declare.

  `:capability` is what every manifest written before there were two means, and is the default
  everywhere a kind is read.
  """
  @spec kinds() :: [:capability | :policy]
  def kinds, do: [:capability, :policy]

  @doc """
  The world a component of `kind` must be in.

  One function, so the signer, the pool, the rollout and the helper's `load` cannot disagree
  about which world a `kind` means. Not configurable, for `world/0`'s reason: admitting a
  component against a world this build does not implement is the lie the linker exists to
  prevent (D5).
  """
  @spec world_for(:capability | :policy) :: String.t()
  def world_for(:policy), do: @policy_world
  def world_for(_capability), do: @world

  @doc """
  The absolute path the helper would be spawned from.

  Always a string, even when nothing is there: `available?/0` is the question about disk,
  and the pool answers `{:error, :unavailable}` rather than raising.
  """
  @spec helper_path() :: String.t()
  def helper_path do
    case System.get_env("OUROBOROS_WASM_HELPER") do
      path when is_binary(path) and path != "" ->
        if absolute_path?(path), do: path, else: configured_helper_path()

      _unset ->
        configured_helper_path()
    end
  end

  defp configured_helper_path do
    case config(:helper_path) do
      path when is_binary(path) and path != "" ->
        path

      _bundled ->
        # The first candidate that exists; failing that, the first candidate as the name
        # a `doctor` would report; failing even that, the bare helper name. Always a
        # string and never `hd([])`, and none of these paths reads the working directory
        # — so a removed cwd cannot raise here and a planted one cannot be selected.
        Enum.find(candidates(), &File.regular?/1) || List.first(candidates()) || @helper
    end
  end

  @doc "Whether a helper is actually on disk. This is the operator opt-in, nothing else."
  @spec available?() :: boolean()
  def available?, do: File.regular?(helper_path())

  @doc "One setting, falling back to the default when the configured value is unusable."
  @spec config(atom()) :: term()
  def config(key) when is_atom(key) do
    default = Keyword.fetch!(@defaults, key)
    configured = Application.get_env(:ouroboros, :wasm, [])

    value =
      if Keyword.keyword?(configured), do: Keyword.get(configured, key, default), else: default

    if valid?(key, value), do: value, else: default
  end

  @doc "Every setting and its effective value, for status surfaces and tests."
  @spec all() :: keyword()
  def all, do: Enum.map(@defaults, fn {key, _default} -> {key, config(key)} end)

  defp valid?(:helper_path, :bundled), do: true

  defp valid?(:helper_path, value),
    do: is_binary(value) and value != "" and absolute_path?(value)

  # All three bounds or none of them. An operator who writes two of the keys gets the
  # documented default for all three rather than a silently half-configured instance, which
  # is the same fallback-on-typo posture as every other setting here — applied to the value
  # this one actually is.
  defp valid?(key, value) when key in @limits_keys do
    Keyword.keyword?(value) and Keyword.keys(value) -- @limit_keys == [] and
      Enum.all?(@limit_keys, fn key ->
        case Keyword.fetch(value, key) do
          {:ok, bound} -> is_integer(bound) and bound > 0
          :error -> false
        end
      end)
  end

  defp valid?(:allow_store_root_override, value), do: is_boolean(value)
  defp valid?(:accept_precompiled, value), do: is_boolean(value)
  defp valid?(:helper_sandbox, value), do: value in [:required, :off]

  # Shape only. What makes an entry *usable* is `helper_readable/0`'s four rules, which need
  # the filesystem and the data directory and so cannot live in a pure validator.
  defp valid?(:helper_readable, value), do: is_list(value)

  defp valid?(key, value) when key in @timeout_keys, do: is_integer(value) and value > 0
  defp valid?(key, value) when key in @byte_keys, do: is_integer(value) and value > 0

  defp absolute_path?(path), do: Path.type(path) == :absolute

  defp candidates do
    # Two candidates, and neither is derived from the working directory (F1). A bare
    # `Path.expand("priv/wasm/…")` and a walk up the cwd's ancestors were both here and both
    # are gone: they let whatever directory the daemon happened to be started in — a cloned
    # repository, a worktree an agent wrote — name the binary this node spawns as its
    # containment boundary, and the bare form additionally raised `File.Error` when the
    # working directory had been removed out from under a running node. What remains is the
    # installation's own `priv/` and the binary that ships beside `ouro`, both of which are
    # as trusted as the release itself.
    [
      priv_helper(),
      sibling_helper(:os.find_executable(~c"ouro"))
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp priv_helper do
    case :code.priv_dir(:ouroboros) do
      priv when is_list(priv) -> Path.join([List.to_string(priv), "wasm", @helper])
      _bad_name -> nil
    end
  end

  defp sibling_helper(false), do: nil

  defp sibling_helper(path) when is_list(path),
    do: Path.join(Path.dirname(List.to_string(path)), @helper)
end
