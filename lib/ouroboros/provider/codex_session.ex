defmodule Ouroboros.Provider.CodexSession do
  @moduledoc """
  Interactive Codex sessions over app-server, so sandbox escalations can ask.

  Coding turns still run through `codex exec --json`. This module is the session
  adapter; the wire mapping lives in `Ouroboros.Provider.Session.Dialect.Codex`.
  `Ouroboros.Provider.CodexAppServer` stays a separate account connection and still
  serves no session methods.
  """

  use Ouroboros.Provider.Session.Adapter, dialect: Ouroboros.Provider.Session.Dialect.Codex
end
