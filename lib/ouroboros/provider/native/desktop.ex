defmodule Ouroboros.Provider.Native.Desktop do
  @moduledoc """
  Computer Use configuration, readiness, and app identity for the native provider.

  This is the Elixir side of `docs/COMPUTER_USE.md`. In Phase 0 it owns no helper
  process and touches no pixels: it reads the `:computer_use` application environment,
  answers whether the feature is genuinely usable on this node, and canonicalises app
  identity. The helper pool, image staging, and per-session snapshot map (D11) arrive in
  later phases; this module is deliberately the honest predicate they will build on.

  ## The one honest predicate

  `enabled?/0` is true only when the flag is on **and** a helper binary actually exists on
  disk. There is no bundled helper in Phase 0, so the second half is false unless
  `OUROBOROS_COMPUTER_USE_HELPER` points at a binary a developer built themselves. That is
  the honesty invariant applied to a feature flag: a node cannot claim it can drive the
  desktop when there is nothing on it that can. `Tools.specs/3` and `Tools.lookup/3` gate
  on this, so an off node never teaches the model a tool name it cannot use (D9).

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

  alias Ouroboros.Provider.Native.Attachments
  alias Ouroboros.Provider.Native.Desktop.Pool

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
    enabled: false,
    helper_path: :bundled,
    handshake_timeout_ms: 5_000,
    state_timeout_ms: 5_000,
    act_timeout_ms: 10_000,
    shutdown_grace_ms: 2_000,
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
  @timeout_keys [:handshake_timeout_ms, :state_timeout_ms, :act_timeout_ms, :shutdown_grace_ms]

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

  True only when the flag is on and the resolved helper binary exists on disk. With no
  bundled helper this is false unless `OUROBOROS_COMPUTER_USE_HELPER` points at a built
  binary — the feature does not claim a capability it cannot back.
  """
  @spec enabled?() :: boolean()
  def enabled?, do: config(:enabled) == true and helper_present?()

  @doc "Whether the resolved helper binary exists on disk as a regular file."
  @spec helper_present?() :: boolean()
  def helper_present?, do: File.regular?(helper_path())

  @doc """
  The absolute path the helper would be spawned from.

  `OUROBOROS_COMPUTER_USE_HELPER` wins, then the configured `:helper_path`, then the
  bundled location. In Phase 0 nothing ships at the bundled location, so it resolves to a
  path that does not exist and `enabled?/0` stays honestly false.
  """
  @spec helper_path() :: String.t()
  def helper_path do
    case System.get_env("OUROBOROS_COMPUTER_USE_HELPER") do
      path when is_binary(path) and path != "" -> path
      _unset -> configured_helper_path()
    end
  end

  defp configured_helper_path do
    case config(:helper_path) do
      path when is_binary(path) and path != "" -> path
      _bundled_or_invalid -> bundled_helper_path()
    end
  end

  defp bundled_helper_path do
    case :code.priv_dir(:ouroboros) do
      priv when is_list(priv) ->
        Path.join([List.to_string(priv), "computer-use", "ouro-computer-use"])

      # An unloaded application has no priv dir; resolve somewhere that does not exist so
      # `helper_present?/0` is false rather than raising.
      _bad_name ->
        "/nonexistent/ouro-computer-use"
    end
  end

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
  def denied_app?(app) when is_binary(app), do: app_alias(app) in denied_app_ids()
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
  A readiness map for operator surfaces, clearly marked not-yet-wired in Phase 0.

  There is no helper process, no capture, and no input in this phase, so `wired` is false
  and `note` says so. Later phases replace this with the helper's own `doctor` output.
  """
  @spec status() :: map()
  def status do
    %{
      enabled: enabled?(),
      flag: config(:enabled) == true,
      helper_path: helper_path(),
      helper_present: helper_present?(),
      denied_app_ids: denied_app_ids(),
      phase: 0,
      wired: false,
      note:
        "Phase 0 stub: no helper process, no screen capture, and no input injection are " <>
          "wired. computer use is not enabled on this node."
    }
  end

  @doc """
  The node's helper pool, started detached on first use.

  There is one pool process per node (D11). It is resolved by name and started unlinked the
  first time a tool needs it, so it outlives the transient task that spawned it; a caller
  racing another to start it gets the winner. `{:error, reason}` when even starting the
  supervisor-less singleton fails, which the caller reports as an honest in-band error.
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
           {:ok, raw} <- run_state(params, context) do
        finish_observe(raw, params, session_dir)
      end

    case outcome do
      %{output: _output} = ok -> {:ok, ok}
      {:error, message} when is_binary(message) -> {:ok, error_result(message)}
      {:error, reason} -> {:ok, error_result(pool_error_message(reason))}
    end
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

  defp finish_observe(raw, params, session_dir) when is_map(raw) do
    include_image = field(params, :include_image) != false
    {images, image_note, staged} = stage_from_raw(raw, session_dir, include_image)
    remember(session_dir, %{state: raw, image: staged})
    %{output: render_state(raw, staged, image_note), is_error: false, images: images}
  end

  defp finish_observe(_raw, _params, _session_dir),
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
      path when is_binary(path) and path != "" -> {:ok, path}
      _absent -> {:error, :missing_path}
    end
  end

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

  defp number(value) when is_number(value), do: value
  defp number(_value), do: 0

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
