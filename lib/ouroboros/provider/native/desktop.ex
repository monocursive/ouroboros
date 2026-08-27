defmodule Ouroboros.Provider.Native.Desktop do
  @moduledoc """
  Computer Use configuration, readiness, and app identity for the native provider.

  This is the Elixir side of `docs/COMPUTER_USE.md`. It owns Computer Use configuration,
  readiness, app identity, observe (`desktop_state`), act (`desktop_act`), staging, and
  the last-state map. A helper on disk is the operator opt-in; `config(:enabled)` and
  `OUROBOROS_COMPUTER_USE=0` can still kill the feature.

  ## The one honest predicate

  `enabled?/0` is true only when the helper binary exists on disk, Computer Use has not
  been killed (`OUROBOROS_COMPUTER_USE=0`), **and** `config(:enabled)` is true. A helper
  on disk is the operator opt-in; the config key is the node-local kill switch that
  `enabled?/0` actually honours.

  ## Configuration bounds

  Same posture as `Ouroboros.Provider.Native.Mcp.Config` — everything here is a bound and a
  malformed value falls back to the shipped default rather than removing the bound. It is
  slightly stricter for caps than the MCP reader, because §4 requires that a *raised* cap
  also fall back: an operator typo must not widen how much a helper may capture, only
  narrow it. Timeouts fall back only when non-positive; a longer timeout is the operator's
  to grant.

  ## The denylist floor

  `denied_app_ids/0` returns the union of the configured list and a baked floor
  (`@denied_app_ids`). The floor is the invariant #9 apps — this runtime's own surfaces,
  the terminals, the OS auth and secret panes — and unioning means an operator may *add*
  denials but a shorter or malformed config can never remove one. The node denylist is
  operator configuration and is not writable through `remember/4` (D12).

  ## Phase 1: helper IO, staging, and the last-state map

  `observe/2` is the read half's runtime (`desktop_state`, §5.2): it resolves the target,
  refuses a denied app before any capture, calls the node's one helper through
  `Ouroboros.Provider.Native.Desktop.Pool`, stages the returned screenshot, records the
  session's last state, and renders the §5.2 text. `stage_image/2` is the honest gate on
  what a helper hands back — sha256 and magic bytes are verified, oversize is refused, and
  the file is written once under `session_dir/desktop/` at `0600`, the same write-once
  discipline as user attachments. The last state lives in the pool's BEAM state, keyed by
  session directory (D11); the helper stays stateless.
  """

  alias Ouroboros.Control.Permissions
  alias Ouroboros.Provider.Native.Attachments
  alias Ouroboros.Provider.Native.Desktop.Pool
  alias Ouroboros.Provider.Native.Paths, as: NativePaths

  # The image formats a Computer Use screenshot may be, verified from the bytes the helper
  # staged (§5.2 / §8.1). Narrower than `Attachments` on purpose: a desktop capture is a
  # jpeg or a png, never a gif or a user's webp.
  @image_media_types ["image/jpeg", "image/png"]

  # The bundle ids Computer Use must never drive, baked so config can only widen the deny,
  # never narrow it. Mirrors `config/config.exs`'s `denied_app_ids` default; the two are
  # kept in step by `test/provider/native/desktop_test.exs`.
  @denied_app_ids [
    "com.ouroboros.desktop",
    "com.ouroboros.tui",
    "com.apple.Terminal",
    "com.googlecode.iterm2",
    "com.mitchellh.ghostty",
    "net.kovidgoyal.kitty",
    "com.apple.systempreferences",
    "com.apple.loginwindow",
    "dev.warp.Warp-Stable",
    "org.alacritty",
    "com.github.wez.wezterm",
    "co.zeit.hyper",
    "org.tabby",
    "com.1password.1password",
    "com.apple.keychainaccess",
    "com.apple.SecurityAgent"
  ]

  # A small alias table so a model may pass `app: "Safari"` and the classifier still names
  # a bundle id the denylist and rules reason about (§16.4, §6.3 step 2). Deliberately tiny
  # and obvious; an unknown name passes through to the helper's own resolver, unchanged.
  @app_aliases %{
    "Safari" => "com.apple.Safari",
    "Calculator" => "com.apple.calculator",
    "Finder" => "com.apple.finder",
    "Notes" => "com.apple.Notes",
    "Mail" => "com.apple.mail",
    "Preview" => "com.apple.Preview",
    "System Settings" => "com.apple.systempreferences",
    "System Preferences" => "com.apple.systempreferences",
    "Terminal" => "com.apple.Terminal"
  }

  @defaults [
    enabled: true,
    act_enabled: true,
    helper_path: :bundled,
    handshake_timeout_ms: 5_000,
    state_timeout_ms: 5_000,
    act_timeout_ms: 10_000,
    shutdown_grace_ms: 2_000,
    stale_ms: 30_000,
    max_frame_bytes: 8 * 1024 * 1024,
    max_image_bytes: 2 * 1024 * 1024,
    max_image_width: 1920,
    max_image_height: 1920,
    max_nodes: 1_000,
    max_depth: 32,
    max_snapshots_per_session: 8,
    jpeg_quality: 80,
    denied_app_ids: @denied_app_ids
  ]

  # Timeouts fall back only when non-positive; a bigger value only makes this node wait
  # longer for its own helper, which is the operator's call to make.
  @timeout_keys [
    :handshake_timeout_ms,
    :state_timeout_ms,
    :act_timeout_ms,
    :shutdown_grace_ms,
    :stale_ms
  ]

  # Caps and limits fall back when non-positive *or raised above the shipped default*: a
  # value over the cap widens what a helper may consume on this node, which a typo must
  # never do (§4).
  @bound_keys [
    :max_frame_bytes,
    :max_image_bytes,
    :max_image_width,
    :max_image_height,
    :max_nodes,
    :max_depth,
    :max_snapshots_per_session
  ]

  @doc """
  Whether Computer Use is genuinely usable on this node.

  True when the helper binary is on disk, `config(:enabled)` is true, and Computer Use
  has not been explicitly killed (`OUROBOROS_COMPUTER_USE=0`). A helper on disk is the
  operator opt-in — they built or installed it. Setting `:enabled` false turns the
  tools off even with a helper present.
  """
  @spec enabled?() :: boolean()
  def enabled?, do: helper_present?() and flag_allows?() and config(:enabled) == true

  @doc "Effective flag: env 0/false kills, env 1/true or an unset env allows."
  @spec flag_allows?() :: boolean()
  def flag_allows? do
    case System.get_env("OUROBOROS_COMPUTER_USE") do
      value when value in ["0", "false"] -> false
      value when value in ["1", "true"] -> true
      _unset -> true
    end
  end

  @doc """
  Whether `desktop_act` is advertised. Default true now that Phase 2 ships injection.
  Operators can set `:act_enabled` false for observe-only.
  """
  @spec act_enabled?() :: boolean()
  def act_enabled?, do: config(:act_enabled) == true

  @doc "Whether the resolved helper binary exists on disk as a regular file."
  @spec helper_present?() :: boolean()
  def helper_present?, do: File.regular?(helper_path())

  @doc """
  The absolute path the helper would be spawned from.

  `OUROBOROS_COMPUTER_USE_HELPER` wins, then a configured absolute `:helper_path`, then
  the first existing candidate: app priv, the checkout `priv/` (mix), or a sibling of
  `ouro` / this executable (the macOS app bundle).
  """
  @spec helper_path() :: String.t()
  def helper_path do
    case System.get_env("OUROBOROS_COMPUTER_USE_HELPER") do
      path when is_binary(path) and path != "" ->
        path

      _unset ->
        case config(:helper_path) do
          path when is_binary(path) and path != "" -> path
          _bundled -> resolve_bundled_helper()
        end
    end
  end

  defp resolve_bundled_helper do
    Enum.find(helper_candidates(), &File.regular?/1) || hd(helper_candidates())
  end

  defp helper_candidates do
    name = "ouro-computer-use"

    [
      priv_helper(name),
      Path.expand(Path.join(["priv", "computer-use", name])),
      walk_priv_helper(name),
      sibling_helper(name, :os.find_executable(~c"ouro")),
      sibling_helper(name, :os.find_executable(~c"ouro-desktop"))
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp walk_priv_helper(name) do
    case File.cwd() do
      {:ok, cwd} ->
        cwd
        |> Stream.iterate(&Path.dirname/1)
        |> Enum.take(6)
        |> Enum.find_value(fn dir ->
          path = Path.join([dir, "priv", "computer-use", name])
          if File.regular?(path), do: path
        end)

      {:error, _reason} ->
        nil
    end
  end

  defp priv_helper(name) do
    case :code.priv_dir(:ouroboros) do
      priv when is_list(priv) -> Path.join([List.to_string(priv), "computer-use", name])
      _bad_name -> nil
    end
  end

  defp sibling_helper(_name, false), do: nil

  defp sibling_helper(name, path) when is_list(path),
    do: Path.join(Path.dirname(List.to_string(path)), name)

  @doc """
  The bundle ids this node refuses to drive, floor unioned with operator config.

  The baked floor can never be removed by a shorter or malformed config; an operator may
  only add ids. This is invariant #9 and D12: ouro and the terminals are always denied.
  """
  @spec denied_app_ids() :: [String.t()]
  def denied_app_ids do
    configured =
      case config(:denied_app_ids) do
        list when is_list(list) -> Enum.filter(list, &(is_binary(&1) and &1 != ""))
        _malformed -> []
      end

    Enum.uniq(@denied_app_ids ++ configured)
  end

  @doc "Whether a claimed or resolved app id is on this node's denylist."
  @spec denied_app?(String.t() | nil) :: boolean()
  def denied_app?(app) when is_binary(app) do
    id = app_alias(app)
    Enum.any?(denied_app_ids(), &(String.downcase(&1) == String.downcase(id)))
  end

  def denied_app?(_app), do: false

  @doc """
  Canonicalises a claimed app name to a bundle id when it is an obvious alias.

  Known names map to their bundle id; anything else passes through unchanged for the
  helper's own resolver to handle. Non-binaries pass through untouched.
  """
  @spec app_alias(term()) :: term()
  def app_alias(name) when is_binary(name), do: Map.get(@app_aliases, name, name)
  def app_alias(name), do: name

  @doc "The alias table, for tests and operator surfaces."
  @spec app_aliases() :: %{String.t() => String.t()}
  def app_aliases, do: @app_aliases

  @doc """
  Node-facing Computer Use readiness for `computer_use.status` (§8.5). Starts nothing.

  Config posture is always reported. `running` is true only when the helper has completed
  its handshake — an idle supervised pool is not running. This never spawns the helper.
  """
  @spec status() :: map()
  def status do
    base = %{
      enabled: enabled?(),
      flag: flag_allows?(),
      helper_path: helper_path(),
      helper_present: helper_present?(),
      denied_app_ids: denied_app_ids(),
      always_allowed_apps: always_allowed_apps(),
      helper_version: helper_version()
    }

    case Process.whereis(Pool) do
      nil ->
        Map.put(base, :running, false)

      pid ->
        ps = Pool.status(pid)
        ready? = ps.phase == :ready

        live =
          %{running: ready?, phase: ps.phase, sessions: ps.sessions}
          |> then(fn live ->
            if ready? and is_map(ps.doctor), do: Map.put(live, :doctor, ps.doctor), else: live
          end)
          |> then(fn live ->
            if ps.phase == :broken,
              do: Map.put(live, :broken_reason, inspect(ps.broken_reason)),
              else: live
          end)

        Map.merge(base, live)
    end
  end

  @doc """
  Starts the helper if needed, waits for handshake, and returns `status/0`.

  Operator surface for `ouro desktop doctor --probe` / `computer_use.probe`. With the
  flag off this is start-nothing and returns the same posture as `status/0` — TCC is
  not prompted on a node that has not opted in. Fleet `status` still starts nothing.
  """
  @spec probe() :: map()
  def probe do
    if enabled?() do
      _ =
        case pool() do
          {:ok, pid} -> Pool.doctor(pid, config(:handshake_timeout_ms) + 1_000)
          {:error, _reason} -> :error
        end
    end

    status()
  end

  @doc """
  Serves one staged screenshot by content hash for `computer_use.artifact` (§8.5).

  Searches the live pool's session dirs by default. When `session_id` is a native
  provider session id whose directory already exists, only that session's `desktop/`
  folder is searched — never created. An unknown or non-64-hex sha is
  `{:error, :not_found}` — never a path traversal. The pool is never started to answer.
  """
  @spec artifact(String.t()) :: {:ok, map()} | {:error, :not_found}
  @spec artifact(String.t(), String.t() | nil) :: {:ok, map()} | {:error, :not_found}
  def artifact(sha, session_id \\ nil)

  def artifact(sha, session_id) when is_binary(sha) do
    with true <- sha =~ ~r/\A[a-f0-9]{64}\z/,
         staged when is_tuple(staged) <- find_staged(sha, artifact_dirs(session_id)) do
      read_artifact(staged)
    else
      _miss -> {:error, :not_found}
    end
  end

  def artifact(_sha, _session_id), do: {:error, :not_found}

  defp find_staged(sha, session_dirs) do
    Enum.find_value(session_dirs, fn dir ->
      Enum.find_value([{"jpg", "image/jpeg"}, {"png", "image/png"}], fn {ext, media} ->
        path = Path.join([dir, "desktop", "#{sha}.#{ext}"])
        if File.regular?(path), do: {path, media}
      end)
    end)
  end

  defp read_artifact({path, media}) do
    case File.read(path) do
      {:ok, bytes} ->
        {:ok, %{bytes: Base.encode64(bytes), media_type: media, size: byte_size(bytes)}}

      _unreadable ->
        {:error, :not_found}
    end
  end

  defp artifact_dirs(session_id) when is_binary(session_id) and session_id != "" do
    case named_session_dir(session_id) do
      path when is_binary(path) -> [path]
      _miss -> []
    end
  end

  defp artifact_dirs(_session_id) do
    case Process.whereis(Pool) do
      pid when is_pid(pid) -> Pool.session_dirs(pid)
      nil -> []
    end
  end

  # Look up an existing native session directory without creating one. A fetch must not
  # mkdir a guessed id.
  defp named_session_dir(id) do
    with :ok <- NativePaths.validate_session_id(id),
         root when is_binary(root) <- native_root(),
         path = Path.join(root, id),
         true <- File.dir?(path) do
      path
    else
      _miss -> nil
    end
  end

  defp native_root do
    case Application.get_env(:ouroboros, :native_data_dir) do
      path when is_binary(path) and path != "" ->
        path

      _unset ->
        case Application.get_env(:ouroboros, :data_dir) do
          path when is_binary(path) and path != "" -> Path.join(path, "native")
          _unset -> nil
        end
    end
  end

  defp always_allowed_apps do
    case Permissions.list([]) do
      {:ok, rules} ->
        rules
        |> Enum.filter(&allow_app_rule?/1)
        |> Enum.map(&app_from_rule/1)
        |> Enum.reject(&is_nil/1)
        |> Enum.uniq()

      _unavailable ->
        []
    end
  end

  defp allow_app_rule?(%{decision: :allow, pattern: pattern}) when is_binary(pattern) do
    case Ouroboros.Control.Permissions.Pattern.parse(pattern) do
      {:ok, %{kind: :computer_use, spec: %{app: app}}} when is_binary(app) -> true
      _other -> false
    end
  end

  defp allow_app_rule?(_rule), do: false

  defp app_from_rule(%{pattern: pattern}) do
    case Ouroboros.Control.Permissions.Pattern.parse(pattern) do
      {:ok, %{kind: :computer_use, spec: %{app: app}}} when is_binary(app) -> app
      _other -> nil
    end
  end

  defp helper_version do
    case Process.whereis(Pool) do
      pid when is_pid(pid) ->
        case Pool.status(pid).doctor do
          %{"version" => version} when is_binary(version) -> version
          %{version: version} when is_binary(version) -> version
          _absent -> nil
        end

      nil ->
        nil
    end
  end

  @doc """
  The node's helper pool. Prefers the supervised singleton; tests without one start
  a detached fallback.
  """
  @spec pool() :: {:ok, pid()} | {:error, term()}
  def pool do
    case Process.whereis(Pool) do
      pid when is_pid(pid) -> {:ok, pid}
      nil -> start_pool()
    end
  end

  defp start_pool do
    case Pool.start([]) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Runs one `desktop_state` observation (§5.2) and returns the loop result shape.

  Resolves the target, refuses a denied app before any capture, calls the helper for a
  `state`, stages the screenshot, records the session's last state (D11), and renders the
  §5.2 text. Always `{:ok, map}` with `map` carrying `output`, `is_error`, and `images`:
  every failure — a denied app, a helper that is down or slow, a screenshot that will not
  stage — is an in-band error the model can read and act on, never a raised turn.

  The helper call goes through `context[:desktop_runner]` when one is supplied (a
  `(method, params, timeout)` function, the injection point tests drive), otherwise through
  the node pool. A screenshot that cannot be staged does not fail the observation: the tree
  still returns, with a warning line, because the accessibility tree is the fact a
  non-vision model needs anyway.
  """
  @spec observe(map(), map()) ::
          {:ok, %{output: String.t(), is_error: boolean(), images: [map()]}}
  def observe(params, context) when is_map(params) and is_map(context) do
    outcome =
      with :ok <- refuse_denied(params),
           {:ok, session_dir} <- session_dir(context),
           :ok <- require_target(params),
           {:ok, raw} <- run_state(params, context) do
        finish_observe(raw, params, session_dir, context)
      end

    case outcome do
      %{output: _output} = ok -> {:ok, ok}
      {:error, message} when is_binary(message) -> {:ok, error_result(message)}
      {:error, reason} -> {:ok, error_result(pool_error_message(reason))}
    end
  end

  defp admit_resolved(raw, params, context) do
    resolved = resolved_app_id(raw)
    claimed = target_app(field(params, :app))
    evaluated = target_app(field(context, :desktop_evaluated_app))

    cond do
      not is_binary(resolved) ->
        {:error, "desktop_state: the helper did not resolve an app identity"}

      denied_app?(resolved) ->
        {:error,
         "desktop_state: #{resolved} is on this node's Computer Use denylist and will not be captured"}

      is_binary(claimed) and claimed != resolved ->
        {:error,
         "desktop_state: resolved #{resolved}, not #{claimed}. Call again naming the resolved app."}

      is_binary(evaluated) and evaluated != resolved ->
        {:error,
         "desktop_state: resolved #{resolved}, not #{evaluated}. Call again naming the resolved app."}

      true ->
        :ok
    end
  end

  defp resolved_app_id(raw) do
    app = field(raw, "app") || %{}
    string(field(app, "id")) || string(field(app, :id))
  end

  @doc """
  Stages one helper screenshot into `session_dir/desktop/`, verified (§8.1).

  Reads the helper's temp path, verifies the bytes are a jpeg or png and that their sha256
  matches the helper's claim, refuses anything over `max_image_bytes`, writes
  `session_dir/desktop/<sha>.<ext>` once at `0600` (the attachments write-once discipline),
  unlinks the temp, and evicts the oldest files past `max_snapshots_per_session`. Returns
  `%{path, media_type, sha256, size}` — the exact part shape the loop and the model encoder
  consume.
  """
  @spec stage_image(map(), String.t()) :: {:ok, map()} | {:error, term()}
  def stage_image(%{} = image, session_dir) when is_binary(session_dir) do
    with {:ok, temp} <- temp_path(image),
         {:ok, bytes} <- read_capped(temp),
         {:ok, media_type} <- verify(bytes, image),
         {:ok, staged} <- persist(bytes, media_type, session_dir) do
      _ = File.rm(temp)
      evict(Path.join(session_dir, "desktop"))
      {:ok, staged}
    end
  end

  def stage_image(_image, _session_dir), do: {:error, :no_image}

  @doc "The last state recorded for a session directory (D11), or `nil`."
  @spec last_state(String.t()) :: map() | nil
  def last_state(session_dir) when is_binary(session_dir) do
    case Process.whereis(Pool) do
      pid when is_pid(pid) -> Pool.last_state(pid, session_dir)
      nil -> nil
    end
  end

  @doc """
  Runs one `desktop_act` (doc §5.3). No image. Failures are in-band.
  """
  @spec act(map(), map()) :: {:ok, %{output: String.t(), is_error: boolean(), images: [map()]}}
  def act(params, context) when is_map(params) and is_map(context) do
    alias Ouroboros.Provider.Native.Tools.DesktopAct

    outcome =
      with :ok <- DesktopAct.validate_args(params),
           {:ok, session_dir} <- session_dir(context),
           {:ok, snapshot} <- load_act_snapshot(params, session_dir),
           :ok <- refuse_denied_act(params, snapshot),
           {:ok, request} <- build_act_request(params, snapshot),
           {:ok, raw} <- run_act(request, context) do
        finish_act(raw)
      end

    case outcome do
      %{output: _output} = ok -> {:ok, ok}
      {:error, message} when is_binary(message) -> {:ok, error_result(message)}
      {:error, reason} -> {:ok, error_result(pool_error_message(reason))}
    end
  end

  @doc """
  Resolves the app this `desktop_act` would operate, without injecting.

  Used by the loop's two-phase gate (§6.3). Last state's resolved id wins unless the call
  retargets via `app`/`window_id`/`title`. Stale or missing last state is an error except
  for a `focus` that names a target.
  """
  @spec resolve_act(map(), String.t() | nil) :: {:ok, String.t()} | {:error, String.t()}
  def resolve_act(params, session_dir) when is_map(params) do
    action = string(field(params, :action))
    claimed = target_app(field(params, :app))
    snapshot = snapshot_for(session_dir)
    last_app = snapshot_app(snapshot)

    cond do
      snapshot_stale?(snapshot) and action != "focus" ->
        {:error, "desktop_act: last desktop_state is stale; call desktop_state again"}

      action == "focus" and is_binary(claimed) ->
        {:ok, claimed}

      is_binary(last_app) and is_binary(claimed) and claimed != last_app ->
        {:error,
         "desktop_act: last state is #{last_app}, not #{claimed}. Call desktop_state again."}

      is_binary(last_app) ->
        {:ok, last_app}

      true ->
        {:error, "desktop_act: call desktop_state first"}
    end
  end

  @doc """
  Fills a missing Computer Use `context.app` from the session's last state.

  A call that retargets by `window_id` or `title` without naming an app is left unset, so
  an Always-allow or session grant for last state's app cannot cover a different window.
  """
  @spec enrich_classified(map(), String.t() | nil) :: map()
  def enrich_classified(%{tool: tool, context: context} = classified, session_dir)
      when tool in ["desktop_state", "desktop_act"] and is_map(context) do
    if is_binary(context[:app]) do
      classified
    else
      if retarget_without_app?(context) do
        classified
      else
        case snapshot_app(snapshot_for(session_dir)) do
          app when is_binary(app) -> %{classified | context: Map.put(context, :app, app)}
          _none -> classified
        end
      end
    end
  end

  def enrich_classified(classified, _session_dir), do: classified

  defp retarget_without_app?(context) do
    is_nil(context[:app]) and
      (is_binary(context[:window_id]) or is_binary(context[:title]))
  end

  @doc """
  Whether this act should ask even after an app allow (§6.6): a secure field, a
  password-ish label, or type-text that looks like a secret.
  """
  @spec sensitive_act?(map(), String.t() | nil) :: boolean()
  def sensitive_act?(params, session_dir) when is_map(params) do
    action = string(field(params, :action))
    text = string(field(params, :text))
    element = act_element(params, snapshot_for(session_dir))

    secret_text?(text) or secure_element?(element) or
      (action in ["type", "key"] and passwordish_element?(element))
  end

  def sensitive_act?(_params, _session_dir), do: false

  @doc "Asks the helper to abort an in-flight act (§7.5). Never starts the pool."
  @spec cancel() :: :ok
  def cancel do
    case Process.whereis(Pool) do
      pid when is_pid(pid) -> Pool.cancel(pid)
      nil -> :ok
    end
  end

  @doc "Drops the last state for a session directory. Called when a session ends."
  @spec forget_state(String.t()) :: :ok
  def forget_state(session_dir) when is_binary(session_dir) do
    case Process.whereis(Pool) do
      pid when is_pid(pid) -> Pool.forget_state(pid, session_dir)
      nil -> :ok
    end
  end

  ## Observe — target, helper call, result assembly

  defp refuse_denied(params) do
    case field(params, :app) do
      app when is_binary(app) and app != "" ->
        if denied_app?(app),
          do:
            {:error,
             "desktop_state: #{app_alias(app)} is on this node's Computer Use denylist and " <>
               "will not be captured"},
          else: :ok

      _no_app ->
        :ok
    end
  end

  defp require_target(params) do
    if Enum.any?([:app, :window_id, :title], fn key ->
         match?(value when is_binary(value) and value != "", field(params, key))
       end) do
      :ok
    else
      {:error,
       "desktop_state: name an app, window_id, or title — untargeted frontmost capture is refused"}
    end
  end

  defp session_dir(context) do
    case field(context, :session_dir) do
      dir when is_binary(dir) and dir != "" ->
        {:ok, dir}

      _absent ->
        {:error,
         "desktop_state: this session has no working directory to stage a screenshot into"}
    end
  end

  defp run_state(params, context) do
    runner = state_runner(context)
    runner.("state", build_state_request(params), config(:state_timeout_ms))
  end

  defp state_runner(context) do
    case field(context, :desktop_runner) do
      fun when is_function(fun, 3) -> fun
      _default -> &pool_request/3
    end
  end

  defp pool_request(method, params, timeout) do
    case pool() do
      {:ok, pid} -> Pool.request(pid, method, params, timeout)
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_state_request(params) do
    %{
      "target" => target(params),
      "include_image" => field(params, :include_image) != false,
      "max_width" => clamp_dim(field(params, :max_width), :max_image_width),
      "max_height" => clamp_dim(field(params, :max_height), :max_image_height),
      "max_bytes" => config(:max_image_bytes),
      "format" => format(field(params, :format)),
      "quality" => clamp_quality(field(params, :quality)),
      "max_nodes" => config(:max_nodes),
      "max_depth" => config(:max_depth)
    }
  end

  defp target(params) do
    %{}
    |> put_if("app_id", target_app(field(params, :app)))
    |> put_if("window_id", string(field(params, :window_id)))
    |> put_if("title", string(field(params, :title)))
  end

  defp target_app(app) when is_binary(app) and app != "", do: app_alias(app)
  defp target_app(_app), do: nil

  defp clamp_dim(value, key) when is_integer(value) and value > 0, do: min(value, config(key))
  defp clamp_dim(_value, key), do: config(key)

  defp clamp_quality(value) when is_integer(value) and value >= 1 and value <= 95, do: value
  defp clamp_quality(_value), do: config(:jpeg_quality)

  defp format("png"), do: "png"
  defp format(_jpeg_or_default), do: "jpeg"

  defp finish_observe(raw, params, session_dir, context) when is_map(raw) do
    case admit_resolved(raw, params, context) do
      :ok ->
        include_image = field(params, :include_image) != false
        {images, image_note, staged} = stage_from_raw(raw, session_dir, include_image)
        remember(session_dir, %{state: raw, image: staged})
        %{output: render_state(raw, staged, image_note), is_error: false, images: images}

      {:error, message} ->
        error_result(message)
    end
  end

  defp finish_observe(_raw, _params, _session_dir, _context),
    do: error_result("the desktop helper returned an unreadable state")

  defp stage_from_raw(raw, session_dir, true) do
    case field(raw, "image") do
      %{} = image ->
        case stage_image(image, session_dir) do
          {:ok, staged} ->
            {[staged], nil, staged}

          {:error, reason} ->
            {[], "the screenshot could not be staged (#{stage_reason(reason)})", nil}
        end

      _no_image ->
        {[], nil, nil}
    end
  end

  defp stage_from_raw(_raw, _session_dir, false), do: {[], nil, nil}

  defp remember(session_dir, last) do
    last = Map.put(last, :at, System.system_time(:millisecond))

    case Process.whereis(Pool) do
      pid when is_pid(pid) -> Pool.remember_state(pid, session_dir, last)
      nil -> :ok
    end
  end

  defp error_result(message), do: %{output: message, is_error: true, images: []}

  defp pool_error_message(reason) do
    case reason do
      :broken ->
        "the desktop helper is not responding on this node"

      {:spawn_failed, _detail} ->
        "the desktop helper could not be started on this node"

      {:pool_unavailable, _detail} ->
        "the desktop helper is not available on this node"

      :starting ->
        "the desktop helper is starting; ask again in a moment"

      :reconnecting ->
        "the desktop helper is reconnecting; ask again in a moment"

      :busy ->
        "the desktop helper is busy with another request"

      :timeout ->
        "the desktop helper did not respond in time"

      {:rpc_error, _code, message} when is_binary(message) ->
        "the desktop helper refused: #{message}"

      _other ->
        "the desktop helper could not capture the screen"
    end
  end

  defp load_act_snapshot(params, session_dir) do
    action = string(field(params, :action))
    snapshot = snapshot_for(session_dir)
    claimed = target_app(field(params, :app))
    last_app = snapshot_app(snapshot)

    cond do
      snapshot_stale?(snapshot) and action != "focus" ->
        {:error, "desktop_act: last desktop_state is stale; call desktop_state again"}

      action != "focus" and is_binary(last_app) and is_binary(claimed) and claimed != last_app ->
        {:error,
         "desktop_act: last state is #{last_app}, not #{claimed}. Call desktop_state again."}

      is_map(snapshot) ->
        {:ok, snapshot}

      action == "focus" and act_has_target?(params) ->
        {:ok, nil}

      true ->
        {:error, "desktop_act: call desktop_state first"}
    end
  end

  defp refuse_denied_act(params, snapshot) do
    app = target_app(field(params, :app)) || snapshot_app(snapshot)

    if denied_app?(app) do
      {:error,
       "desktop_act: #{app_alias(app)} is on this node's Computer Use denylist and will not be driven"}
    else
      :ok
    end
  end

  defp run_act(request, context) do
    runner = state_runner(context)
    runner.("act", request, config(:act_timeout_ms))
  end

  defp build_act_request(params, snapshot) do
    action = string(field(params, :action))
    raw = snapshot_raw(snapshot)

    {:ok,
     %{
       "action" => action,
       "target" => act_target(params, raw),
       "element" => act_element(params, snapshot),
       "point" => act_point(params),
       "from" => act_named_point(params, :from_x, :from_y),
       "to" => act_named_point(params, :to_x, :to_y),
       "text" => string(field(params, :text)),
       "key" => string(field(params, :key)),
       "button" => string(field(params, :button)) || "left",
       "direction" => string(field(params, :direction)),
       "pages" => field(params, :pages) || 1,
       "require_focus" => field(params, :require_focus) != false,
       "coordinate_space" => coordinate_space(raw)
     }
     |> reject_nils_map()}
  end

  defp finish_act(raw) when is_map(raw) do
    ok = field(raw, "ok") != false
    error = string(field(raw, "error"))
    landing = string(field(raw, "landing"))
    backend = string(field(raw, "backend"))
    app = string(field(raw, "app_id"))
    window = string(field(raw, "window_id"))

    lines =
      [
        if(ok, do: "ok=true", else: "ok=false"),
        backend && "backend=#{backend}",
        app && "app=#{app}",
        window && "window=#{window}",
        landing,
        error && "error: #{error}"
      ]
      |> Enum.reject(&is_nil/1)

    warnings = raw |> field("warnings") |> List.wrap() |> Enum.filter(&is_binary/1)

    output =
      case warnings do
        [] -> Enum.join(lines, "\n")
        list -> Enum.join(lines ++ ["warnings:" | Enum.map(list, &("  - " <> &1))], "\n")
      end

    %{output: output, is_error: not ok or is_binary(error), images: []}
  end

  defp finish_act(_raw), do: error_result("the desktop helper returned an unreadable act result")

  defp snapshot_for(session_dir) when is_binary(session_dir), do: last_state(session_dir)
  defp snapshot_for(_session_dir), do: nil

  defp snapshot_raw(%{state: raw}) when is_map(raw), do: raw
  defp snapshot_raw(raw) when is_map(raw), do: raw
  defp snapshot_raw(_other), do: nil

  defp snapshot_app(snapshot) do
    raw = snapshot_raw(snapshot)
    app = raw && (field(raw, "app") || %{})
    string(field(app || %{}, "id"))
  end

  defp snapshot_stale?(nil), do: false

  defp snapshot_stale?(snapshot) do
    case snapshot_at(snapshot) do
      at when is_integer(at) ->
        System.system_time(:millisecond) - at > config(:stale_ms)

      _missing ->
        true
    end
  end

  defp snapshot_at(%{at: at}) when is_integer(at), do: at
  defp snapshot_at(%{"at" => at}) when is_integer(at), do: at
  defp snapshot_at(_other), do: nil

  defp act_has_target?(params) do
    Enum.any?([:app, :window_id, :title], fn key ->
      match?(value when is_binary(value) and value != "", field(params, key))
    end)
  end

  defp act_target(params, raw) do
    window = (raw && field(raw, "window")) || %{}

    %{}
    |> put_if("app_id", target_app(field(params, :app)) || snapshot_app(%{state: raw}))
    |> put_if("window_id", string(field(params, :window_id)) || string(field(window, "id")))
    |> put_if("title", string(field(params, :title)))
  end

  defp act_element(params, snapshot) do
    index = field(params, :element_index)
    raw = snapshot_raw(snapshot)
    nodes = (raw && field(raw, "nodes")) || []

    cond do
      is_integer(index) and is_list(nodes) ->
        Enum.find(nodes, fn node -> integer(field(node, "index")) == index end)

      true ->
        nil
    end
  end

  defp act_point(params) do
    x = field(params, :x)
    y = field(params, :y)

    if is_integer(x) and is_integer(y), do: %{"x" => x, "y" => y}
  end

  defp act_named_point(params, xk, yk) do
    x = field(params, xk)
    y = field(params, yk)

    if is_integer(x) and is_integer(y), do: %{"x" => x, "y" => y}
  end

  defp coordinate_space(nil), do: nil

  defp coordinate_space(raw) do
    window = field(raw, "window") || %{}
    bounds = field(window, "bounds") || %{}
    image = field(raw, "image") || %{}

    origin_x =
      optional_number(field(image, "origin_x")) || optional_number(field(bounds, "x"))

    origin_y =
      optional_number(field(image, "origin_y")) || optional_number(field(bounds, "y"))

    width = optional_int(field(image, "coordinate_width")) || optional_int(field(bounds, "w"))
    height = optional_int(field(image, "coordinate_height")) || optional_int(field(bounds, "h"))
    scale = optional_number(field(image, "scale")) || 1.0

    if is_number(origin_x) and is_number(origin_y) and is_integer(width) and is_integer(height) and
         width > 0 and height > 0 and is_number(scale) and scale > 0 do
      %{
        "origin_x" => origin_x,
        "origin_y" => origin_y,
        "width" => width,
        "height" => height,
        "scale" => scale
      }
    end
  end

  defp secret_text?(text) when is_binary(text) do
    String.contains?(text, "sk-") or String.contains?(text, "ghp_") or
      (byte_size(text) > 32 and high_entropy?(text))
  end

  defp secret_text?(_text), do: false

  defp high_entropy?(text) do
    uniq = text |> String.graphemes() |> Enum.uniq() |> length()
    uniq / max(String.length(text), 1) > 0.6
  end

  defp secure_element?(%{} = element) do
    role = string(field(element, "role")) || ""
    String.downcase(role) in ["axsecuretextfield", "securetextfield"]
  end

  defp secure_element?(_element), do: false

  defp passwordish_element?(%{} = element) do
    name = String.downcase(string(field(element, "name")) || "")

    String.contains?(name, "password") or String.contains?(name, "passwd") or
      String.contains?(name, "pin")
  end

  defp passwordish_element?(_element), do: false

  defp reject_nils_map(map) do
    Enum.reduce(map, %{}, fn
      {_key, nil}, acc -> acc
      {key, value}, acc -> Map.put(acc, key, value)
    end)
  end

  ## §5.2 rendering

  defp render_state(raw, staged, image_note) do
    [
      app_line(raw),
      window_line(raw),
      image_line(raw, staged),
      readiness_line(raw),
      focused_line(raw),
      nodes_block(raw),
      offscreen_line(raw),
      warnings_block(raw, image_note)
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n")
  end

  defp app_line(raw) do
    app = field(raw, "app") || %{}
    id = string(field(app, "id"))
    name = string(field(app, "name"))

    cond do
      id && name -> "app: #{id} (#{name})"
      id -> "app: #{id}"
      name -> "app: #{name}"
      true -> "app: (unresolved)"
    end
  end

  defp window_line(raw) do
    case field(raw, "window") do
      %{} = window ->
        "window: #{inspect(string(field(window, "title")) || "")} id=#{string(field(window, "id")) || "?"} " <>
          "focused=#{boolean(field(window, "focused"))} bounds=#{bounds(field(window, "bounds"))}"

      _absent ->
        nil
    end
  end

  defp image_line(_raw, nil), do: nil

  defp image_line(raw, staged) do
    image = field(raw, "image") || %{}
    width = integer(field(image, "width"))
    height = integer(field(image, "height"))
    fmt = if staged.media_type == "image/png", do: "png", else: "jpeg"

    coord =
      "coord=#{integer(field(image, "coordinate_width"))}x#{integer(field(image, "coordinate_height"))}"

    "image: #{width}x#{height} #{fmt} q=#{quality(field(image, "quality"))} " <>
      "scale=#{number(field(image, "scale"))} #{coord} sha=#{staged.sha256}"
  end

  defp readiness_line(raw) do
    r = field(raw, "readiness") || %{}

    "readiness: screenshot=#{readiness(field(r, "screenshot"))} ax=#{readiness(field(r, "ax"))} " <>
      "input=#{readiness(field(r, "input"))}"
  end

  defp focused_line(raw) do
    case field(raw, "focused_element") do
      %{} = fe ->
        "focused_element: #{string(field(fe, "role")) || "?"} #{inspect(string(field(fe, "name")) || "")} " <>
          "editable=#{boolean(field(fe, "editable"))}"

      _absent ->
        nil
    end
  end

  defp nodes_block(raw) do
    nodes = field(raw, "nodes")
    nodes = if is_list(nodes), do: nodes, else: []
    ["nodes (#{length(nodes)}):" | Enum.map(nodes, &node_line/1)] |> Enum.join("\n")
  end

  defp node_line(node) when is_map(node) do
    index = integer(field(node, "index"))
    role = string(field(node, "role")) || "?"
    name = string(field(node, "name")) || ""
    actions = field(node, "actions")

    action_suffix =
      case actions do
        list when is_list(list) and list != [] -> " (#{Enum.map_join(list, ",", &to_string/1)})"
        _none -> ""
      end

    "  [#{index}] #{role} #{inspect(name)}#{action_suffix}"
  end

  defp node_line(_node), do: "  [?] (unreadable node)"

  defp offscreen_line(raw), do: "offscreen: #{boolean(field(raw, "offscreen"))}"

  defp warnings_block(raw, image_note) do
    warnings =
      (raw |> field("warnings") |> List.wrap() |> Enum.filter(&is_binary/1)) ++
        List.wrap(image_note)

    case warnings do
      [] -> nil
      list -> "warnings:\n" <> Enum.map_join(list, "\n", &("  - " <> &1))
    end
  end

  ## Staging internals

  defp temp_path(image) do
    case field(image, "path") do
      path when is_binary(path) and path != "" ->
        if helper_temp?(path), do: {:ok, path}, else: {:error, :path_outside_temp}

      _absent ->
        {:error, :missing_path}
    end
  end

  # The helper writes `$TMPDIR/ouro-cu/{sha}.{ext}`. A path outside that directory is
  # refused so a confused or hostile helper cannot make Elixir read an arbitrary file.
  defp helper_temp?(path) do
    expanded = Path.expand(path)
    dir = Path.dirname(expanded)

    Path.basename(dir) == "ouro-cu" and under_tmp?(Path.dirname(dir)) and
      ".." not in Path.split(path)
  end

  defp under_tmp?(dir) do
    tmp = strip_private(Path.expand(System.tmp_dir!()))
    dir = strip_private(dir)
    dir == tmp or String.starts_with?(dir, tmp <> "/")
  end

  defp strip_private("/private" <> rest), do: rest
  defp strip_private(path), do: path

  defp read_capped(path) do
    max = config(:max_image_bytes)

    case File.open(path, [:read, :binary], fn file -> IO.binread(file, max + 1) end) do
      {:ok, bytes} when is_binary(bytes) and byte_size(bytes) > max -> {:error, :too_large}
      {:ok, bytes} when is_binary(bytes) and byte_size(bytes) > 0 -> {:ok, bytes}
      {:ok, _empty} -> {:error, :empty}
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify(bytes, image) do
    digest = sha256(bytes)
    media = Attachments.media_type(bytes)
    claimed = claimed_sha(image)

    cond do
      media not in @image_media_types -> {:error, {:not_an_image, media}}
      byte_size(bytes) > config(:max_image_bytes) -> {:error, :too_large}
      is_binary(claimed) and claimed != digest -> {:error, :sha_mismatch}
      true -> {:ok, media}
    end
  end

  defp persist(bytes, media_type, session_dir) do
    digest = sha256(bytes)
    dir = Path.join(session_dir, "desktop")
    path = Path.join(dir, digest <> extension(media_type))

    with :ok <- mkdir_private(dir),
         :ok <- write_once(path, bytes) do
      {:ok, %{path: path, media_type: media_type, sha256: digest, size: byte_size(bytes)}}
    end
  end

  # Keep the newest `max_snapshots_per_session` files and remove the rest, oldest first. The
  # amendment Δ2 case — a sha a still-live message references — is handled at the encoder,
  # which degrades a missing tool image to a text marker rather than raising: eviction here
  # can be simple because it can never fail a turn.
  defp evict(dir) do
    keep = config(:max_snapshots_per_session)

    case File.ls(dir) do
      {:ok, names} ->
        files =
          names
          |> Enum.map(&Path.join(dir, &1))
          |> Enum.filter(&File.regular?/1)

        if length(files) > keep do
          files
          |> Enum.map(fn path -> {path, mtime(path)} end)
          |> Enum.sort_by(fn {_path, time} -> time end)
          |> Enum.drop(-keep)
          |> Enum.each(fn {path, _time} -> File.rm(path) end)
        end

        :ok

      _unreadable ->
        :ok
    end
  end

  defp claimed_sha(image) do
    case field(image, "sha256") do
      sha when is_binary(sha) -> String.downcase(sha)
      _absent -> nil
    end
  end

  defp mkdir_private(path) do
    with :ok <- File.mkdir_p(path), do: File.chmod(path, 0o700)
  end

  defp write_once(path, bytes) do
    case File.write(path, bytes, [:binary, :exclusive]) do
      :ok -> File.chmod(path, 0o600)
      {:error, :eexist} -> verify_existing(path, bytes)
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_existing(path, bytes) do
    case File.read(path) do
      {:ok, ^bytes} -> :ok
      {:ok, _other} -> {:error, {:sha_collision, path}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp extension("image/png"), do: ".png"
  defp extension(_jpeg), do: ".jpg"

  defp stage_reason({:not_an_image, media}), do: "not a jpeg or png: #{inspect(media)}"
  defp stage_reason(:too_large), do: "over the #{config(:max_image_bytes)}-byte limit"
  defp stage_reason(:sha_mismatch), do: "sha256 did not match the helper's claim"
  defp stage_reason(reason), do: inspect(reason)

  defp sha256(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

  defp mtime(path) do
    case File.stat(path, time: :posix) do
      {:ok, %File.Stat{mtime: mtime}} -> mtime
      _unreadable -> 0
    end
  end

  ## Small field readers, tolerant of atom- or string-keyed maps

  defp field(map, key) when is_map(map) and is_atom(key),
    do: Map.get(map, key, Map.get(map, Atom.to_string(key)))

  defp field(map, key) when is_map(map) and is_binary(key) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> atom_key(map, key)
    end
  end

  defp field(_map, _key), do: nil

  defp atom_key(map, key) do
    Map.get(map, String.to_existing_atom(key))
  rescue
    ArgumentError -> nil
  end

  defp put_if(map, _key, nil), do: map
  defp put_if(map, key, value), do: Map.put(map, key, value)

  defp string(value) when is_binary(value) and value != "", do: value
  defp string(_value), do: nil

  defp integer(value) when is_integer(value), do: value
  defp integer(_value), do: 0

  defp optional_int(value) when is_integer(value), do: value
  defp optional_int(_value), do: nil

  defp number(value) when is_number(value), do: value
  defp number(_value), do: 0

  defp optional_number(value) when is_number(value), do: value
  defp optional_number(_value), do: nil

  defp quality(value) when is_integer(value) and value >= 1 and value <= 95, do: value
  defp quality(_value), do: config(:jpeg_quality)

  defp boolean(true), do: true
  defp boolean(_value), do: false

  defp readiness(value) when value in ["ok", "unknown", "error", "unavailable"], do: value
  defp readiness(_value), do: "unknown"

  defp bounds(%{} = bounds) do
    "#{integer(field(bounds, "x"))},#{integer(field(bounds, "y"))}," <>
      "#{integer(field(bounds, "w"))},#{integer(field(bounds, "h"))}"
  end

  defp bounds(_absent), do: "?"

  @doc "One effective setting, after the shipped-default fallback."
  @spec config(atom()) :: term()
  def config(key) when is_atom(key) do
    default = Keyword.fetch!(@defaults, key)
    configured = Application.get_env(:ouroboros, :computer_use, [])

    value =
      if Keyword.keyword?(configured), do: Keyword.get(configured, key, default), else: default

    if valid?(key, default, value), do: value, else: default
  end

  @doc "Every setting and its effective value, for status surfaces and tests."
  @spec all() :: keyword()
  def all, do: Enum.map(@defaults, fn {key, _default} -> {key, config(key)} end)

  defp valid?(:enabled, _default, value), do: is_boolean(value)
  defp valid?(:act_enabled, _default, value), do: is_boolean(value)
  defp valid?(:helper_path, _default, :bundled), do: true
  defp valid?(:helper_path, _default, value), do: is_binary(value) and value != ""
  defp valid?(:denied_app_ids, _default, value), do: is_list(value)

  defp valid?(:jpeg_quality, _default, value),
    do: is_integer(value) and value >= 1 and value <= 95

  defp valid?(key, _default, value) when key in @timeout_keys, do: is_integer(value) and value > 0

  defp valid?(key, default, value) when key in @bound_keys,
    do: is_integer(value) and value > 0 and value <= default

  defp valid?(_key, _default, _value), do: true
end
