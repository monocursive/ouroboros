defmodule Ouroboros.Provider.Session.ACP do
  @moduledoc """
  Interactive ACP sessions on the shared JSONL runtime.

  Kimi and OpenCode use this instead of Harness's copy-pasted ACP transport so a
  server-to-client request that is not `session/request_permission` is refused as
  method-not-found rather than mistaken for a notification. A future ACP CLI is
  the same dialect: point `cli_path` at it, keep argv `acp`.
  """

  use Ouroboros.Provider.Session.Adapter, dialect: Ouroboros.Provider.Session.Dialect.ACP
end
