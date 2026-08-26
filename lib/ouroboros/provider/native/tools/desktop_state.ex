defmodule Ouroboros.Provider.Native.Tools.DesktopState do
  @moduledoc """
  Observe one desktop app: a size-bounded screenshot and a compact accessibility tree.

  Computer Use's read half (`docs/COMPUTER_USE.md` §5.2). It classifies as `mode: :read`
  — a plan may look at the screen, it just may not click (D3) — and it is the observe step
  every `desktop_act` is checked against.

  ## Phase 1 — observe

  `run/2` delegates to `Ouroboros.Provider.Native.Desktop.observe/2`, which resolves the
  target, refuses a denied app before any capture, drives the node's helper for a `state`,
  stages the screenshot under `session_dir/desktop/`, records the session's last state
  (D11), and renders the §5.2 text. The result carries `images: [%{path, media_type,
  sha256, size}]` — the seam the loop turns into a multimodal tool message (§8.1). Every
  failure is in-band (`is_error: true`, no image): the tool never raises a turn, and it
  never returns a screenshot it did not actually stage. The tool is absent from the tool
  list altogether unless `Ouroboros.Provider.Native.Desktop.enabled?/0` and a workspace are
  both present (§5.1), so a model only ever sees this name on a node that can answer it.
  """

  alias Ouroboros.Provider.Native.Desktop

  use Jido.Action,
    name: "desktop_state",
    description:
      "Capture a size-bounded screenshot and a compact accessibility tree for one desktop " <>
        "app or window. Call this before desktop_act. Prefer read, bash, and MCP when the " <>
        "fact you need is in the workspace or a structured API. Do not use this to drive " <>
        "Terminal, ouro, or ouro-desktop.",
    schema: [
      app: [
        type: :string,
        doc: "Which app to observe: a bundle id, app name, or app id. Defaults to the frontmost."
      ],
      window_id: [
        type: :string,
        doc: "A helper-issued window id from a prior desktop_state, to re-observe that window."
      ],
      title: [type: :string, doc: "A window-title substring, to pick among an app's windows."],
      include_image: [
        type: :boolean,
        default: true,
        doc: "Whether to include the screenshot. false returns the accessibility tree only."
      ],
      max_width: [type: :integer, doc: "Max screenshot width in pixels. Capped by node config."],
      max_height: [type: :integer, doc: "Max screenshot height in pixels. Capped by node config."],
      format: [type: :string, default: "jpeg", doc: "Image format: jpeg (default) or png."],
      quality: [
        type: :integer,
        doc: "JPEG quality 1-95 (jpeg only). Defaults to the node's configured quality."
      ]
    ]

  @not_enabled "computer use is not enabled on this node"

  @impl true
  def run(params, context) do
    params = if is_map(params), do: params, else: %{}
    context = if is_map(context), do: context, else: %{}

    # The tool is only listed when `enabled?/0`, but a direct caller (a test, a replay) may
    # reach `run/2` on an off node; answer honestly rather than spawning a helper that the
    # config says must not run.
    if Desktop.enabled?() or Map.has_key?(context, :desktop_runner),
      do: Desktop.observe(params, context),
      else: {:ok, %{output: @not_enabled, is_error: true, images: []}}
  end
end
