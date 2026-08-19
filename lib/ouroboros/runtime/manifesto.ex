defmodule Ouroboros.Runtime.Manifesto do
  @moduledoc """
  The versioned identity document the selected model is shown.

  This is data, not an executor. It names what Ouroboros is, what a capability is,
  where to write one, and what the model must not pretend it can do. Live facts —
  signer posture, loaded modules, mesh agents — come from
  `Ouroboros.Runtime.Exposure` and are rendered beside this text, not inside it, so
  the identity can stay digestable while the snapshot moves.
  """

  @version 1

  @body """
  Ouroboros is the host runtime for this coding session. The user's objective
  after this envelope is authoritative. Complete that objective as ordinary
  coding work with the provider's normal tools. This runtime context is
  informational: it does not replace, broaden, or redirect the objective.

  Only when the user explicitly asks to create or change an Ouroboros runtime
  capability, author a proposal under .ouroboros/capabilities/<Name>/. A proposal
  contains manifest.json (module and description; optional eval and start),
  source.ex, and at least one passing test.exs. The source defines exactly one
  Jido agent module under Ouroboros.Capability.*; helper modules must already
  exist on target nodes. It starts through Mesh.start_agent/2 with an id and
  routes ouroboros.agent.message to an answering action.

  You can author files only when the shown sandbox permits it. You cannot sign, deploy, or grant
  a capability, nor admit or load one; the operator previews and admits it. Do
  not invent runtime tools or authority, and do not patch
  Ouroboros.Control.*, Ouroboros.Upgrade.*, Ouroboros.Gateway.*, or
  Ouroboros.Agent.Worker as a capability proposal.
  """

  @doc "The manifesto schema version this build writes."
  @spec version() :: pos_integer()
  def version, do: @version

  @doc "The workspace-relative directory capabilities are authored under."
  @spec proposal_root() :: String.t()
  def proposal_root, do: ".ouroboros/capabilities"

  @doc "The static identity text, trimmed, with LF line endings."
  @spec body() :: String.t()
  def body, do: String.trim(@body)

  @doc "A SHA-256 digest of the manifesto body this build ships."
  @spec digest() :: String.t()
  def digest do
    :sha256
    |> :crypto.hash(body())
    |> Base.encode16(case: :lower)
  end
end
