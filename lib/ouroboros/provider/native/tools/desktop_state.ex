defmodule Ouroboros.Provider.Native.Tools.DesktopState do
  @moduledoc """
  Observe one desktop app: a size-bounded screenshot and a compact accessibility tree.

  Computer Use's read half (`docs/COMPUTER_USE.md` §5.2). It classifies as `mode: :read`
  — a plan may look at the screen, it just may not click (D3) — and it is the observe step
  every `desktop_act` is checked against.

  ## Phase 0

  This is the contract, not the capability. The helper that owns pixels and accessibility
  trees does not exist yet, so `run/2` returns an in-band error saying Computer Use is not
  enabled on this node rather than pretending to have looked at anything. That is the
  honesty invariant: a stub says it is a stub. The tool is absent from the tool list
  altogether unless `Ouroboros.Provider.Native.Desktop.enabled?/0` and a workspace are both
  present (§5.1), so a model only ever sees this name on a node that could, in a later
  phase, answer it.
  """

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
  def run(_params, _context) do
    # Phase 0: no helper IO. Every well-formed call reports honestly that the capability is
    # not wired on this node rather than returning a screenshot it did not take.
    {:ok, %{output: @not_enabled, is_error: true}}
  end
end
