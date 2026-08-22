defmodule Ouroboros.Control.Permissions.Seam do
  @moduledoc """
  The two places a provider asks first, and what the engine says there.

  `Dialect.ACP.approval_request/2` and `Dialect.Codex.approval_request/2` are the only
  pre-tool points this runtime has: everywhere else a vendor CLI has already run the tool
  by the time Ouroboros sees an event ([M3 §5c](../../../../docs/research/agent-ux-2026/M3-provider-tool-layer-map.md)).
  Both are called inside the `Session.Jsonl` process, and both receive only a method and
  the provider's params — no session id, no workspace, no provider name.

  ## How the principal gets here

  `bind/3` is called from each dialect's `command/2`, which runs in `Session.Jsonl.init/1`
  and is handed both the request and the context. It stores the session id, provider, and
  cwd in that process's dictionary; `decide/3` reads them back. The dictionary is the
  right shape for this and not a shortcut: the value belongs to exactly one process, is
  written once before any frame is read, and dies with the process it describes.

  **An unbound seam asks.** A dialect function called outside a session process — a unit
  test, a future caller — evaluates with no session id, so no `:session`-scoped rule
  matches and nothing about the principal is invented. That is the safe direction, and it
  is why the existing dialect tests keep passing untouched.

  ## What each provider carries

  ACP `session/request_permission` gives a `toolCall` with `kind`, `title`, `rawInput`,
  and `locations`; the command line is in `rawInput.command` and the paths in `locations`.
  Codex names the shape in the method: `item/commandExecution/requestApproval` carries
  `command` and `cwd`, `item/fileChange/requestApproval` carries changed paths, and
  `item/permissions/requestApproval` carries a `grantRoot`. Both are mapped onto the one
  request shape `Ouroboros.Control.Permissions.evaluate/1` takes.

  ## What the seam does with the answer

    * `:allow` — answer the provider immediately with its own approve option. The decision
      is already in the ledger; `evaluate/1` put it there before returning.
    * `:deny` — answer with the provider's own refusal, and say which rule refused it.
    * `:ask` — emit `approval_requested` exactly as before, with one field added:
      `suggested_rule`, the pattern that would stop the question recurring. A client can
      render "don't ask again for `cargo *`" without inventing a rule language of its own,
      which is Codex's `acceptWithExecpolicyAmendment` idea with the amendment computed
      server-side.
  """

  alias Ouroboros.Control.Permissions

  @binding :ouroboros_permission_principal

  @type verdict :: {:allow, map()} | {:deny, map()} | {:ask, map()}

  @doc """
  Remembers which session this process speaks for. Called from a dialect's `command/2`.

  Returns `:ok` whatever it is given: a seam that could not be bound asks rather than
  failing a session that would otherwise have started.
  """
  @spec bind(term(), term(), atom()) :: :ok
  def bind(request, context, transport) do
    Process.put(@binding, %{
      session_id: field(context, :session_id),
      provider: field(context, :provider),
      workspace: field(request, :cwd),
      transport: transport,
      node: node()
    })

    :ok
  rescue
    _error -> :ok
  end

  @doc "The principal this process speaks for, or an empty one."
  @spec principal() :: map()
  def principal do
    case Process.get(@binding) do
      %{} = bound -> bound
      _unbound -> %{session_id: nil, provider: nil, workspace: nil, transport: nil, node: node()}
    end
  end

  @doc """
  Decides one provider approval request.

  `payload` is the payload the dialect would have emitted; on `:ask` it comes back with
  `suggested_rule` added, and on `:allow`/`:deny` the caller answers the provider instead
  of emitting anything.
  """
  @spec decide(:acp | :app_server, String.t(), map(), map()) :: verdict()
  def decide(dialect, method, params, payload) do
    bound = principal()
    request = request(dialect, method, params, bound)

    case Permissions.evaluate(request) do
      {:allow, ref} -> {:allow, ref}
      {:deny, ref} -> {:deny, ref}
      {:ask, _reason} -> {:ask, suggested(payload, request)}
    end
  rescue
    # The seam can only ever make a decision *narrower*. If it cannot make one at all,
    # the approval reaches the human exactly as it did before this module existed.
    _error -> {:ask, payload}
  catch
    _kind, _reason -> {:ask, payload}
  end

  @doc """
  Records a human's answer, and turns a session-scoped one into a rule.

  `stash` is the dialect's own approval stash, which carries the provider params the
  request was built from. `decision_id` is stable per session and provider request id, so
  a retried acknowledgement records once.
  """
  @spec answered(:acp | :app_server, String.t(), map(), map()) :: :ok
  def answered(dialect, decision_id, stash, response) do
    bound = principal()
    params = Map.get(stash, :params) || %{}
    method = Map.get(stash, :method) || ""
    request = request(dialect, method, params, bound)

    _ =
      Permissions.record(decision_id, %{
        decision: response.decision,
        scope: response.scope,
        actor: :human,
        rule_ref: nil,
        reason: response.reason,
        request: request
      })

    _ = remember(response, request, bound)
    :ok
  rescue
    _error -> :ok
  catch
    _kind, _reason -> :ok
  end

  @doc """
  Drops the rules this session remembered. Called when its provider process terminates.

  A `:session` rule is one human's "don't ask again *here*". Forgetting it when the
  session ends is what makes that scope mean what it says, and it is also what keeps the
  store from growing by one rule per conversation this node has ever had.
  """
  @spec forget_session() :: :ok
  def forget_session do
    case principal().session_id do
      session_id when is_binary(session_id) -> Permissions.forget_session(session_id)
      _unbound -> :ok
    end

    :ok
  rescue
    _error -> :ok
  catch
    _kind, _reason -> :ok
  end

  @doc "The stable ledger id for one provider approval on one session."
  @spec decision_id(String.t()) :: String.t()
  def decision_id(request_id) do
    session = principal().session_id || "unattributed"
    "approval-" <> session <> ":" <> to_string(request_id)
  end

  @doc "A refusal reason that names the rule, for the provider and for the transcript."
  @spec refusal(map()) :: String.t()
  def refusal(%{scope: scope, pattern: pattern}),
    do: "refused by the #{scope}-scope permission rule #{pattern}"

  def refusal(_ref), do: "refused by a permission rule"

  # A "don't ask again" answer is exactly a rule the human just wrote by hand. `:once`
  # writes nothing, because that is what once means.
  defp remember(%{decision: decision, scope: :session}, request, bound) do
    with pattern when is_binary(pattern) <- Permissions.suggest(request) do
      Permissions.remember(
        bound,
        pattern,
        if(decision == :approve, do: :allow, else: :deny),
        :session
      )
    end
  end

  defp remember(_response, _request, _bound), do: :ok

  defp suggested(payload, request) do
    case Permissions.suggest(request) do
      nil -> payload
      pattern -> Map.put(payload, "suggested_rule", pattern)
    end
  end

  # ── provider → request ─────────────────────────────────────────────────────────────

  defp request(:acp, _method, params, bound) do
    call = params["toolCall"] || params["tool_call"] || %{}
    raw = call["rawInput"] || call["raw_input"] || %{}
    command = call["command"] || raw["command"]
    kind = call["kind"] || raw["kind"]

    base(bound)
    |> Map.merge(%{
      tool: acp_tool(call, raw, kind),
      command: text(command),
      paths: acp_paths(call, raw),
      mode: acp_mode(kind, command),
      domains: domains(raw),
      context: context(bound, %{"kind" => kind, "title" => call["title"]})
    })
  end

  defp request(:app_server, method, params, bound) do
    command = params["command"]

    base(bound)
    |> Map.merge(%{
      tool: codex_tool(method),
      command: text(command),
      paths: codex_paths(method, params),
      mode: codex_mode(method),
      domains: [],
      context: context(bound, %{"kind" => codex_kind(method)})
    })
  end

  defp base(bound) do
    %{
      principal: %{
        session_id: bound.session_id,
        provider: bound.provider,
        node: bound.node
      }
    }
  end

  defp context(bound, extra) do
    extra
    |> Map.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.put(:workspace, bound.workspace)
  end

  # ACP's tool `kind` taxonomy is `read | edit | delete | move | search | execute | think |
  # fetch | other`; the tool's own name is better when it has one, because that is what an
  # operator writes in `Tool(...)`.
  defp acp_tool(call, raw, kind) do
    call["name"] || raw["name"] || call["toolName"] || kind || "unknown"
  end

  defp acp_mode(_kind, command) when is_binary(command) and command != "", do: :execute
  defp acp_mode("read", _command), do: :read
  defp acp_mode("search", _command), do: :read
  defp acp_mode("fetch", _command), do: :network
  defp acp_mode("execute", _command), do: :execute
  defp acp_mode(_kind, _command), do: :write

  defp acp_paths(call, raw) do
    locations =
      case call["locations"] do
        list when is_list(list) -> Enum.map(list, &location_path/1)
        _other -> []
      end

    (locations ++ [raw["path"], raw["file_path"], raw["abs_path"]])
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.uniq()
  end

  defp location_path(%{"path" => path}) when is_binary(path), do: path
  defp location_path(path) when is_binary(path), do: path
  defp location_path(_location), do: nil

  defp domains(raw) do
    [raw["url"], raw["domain"], raw["host"]]
    |> Enum.filter(&is_binary/1)
    |> Enum.map(&host/1)
    |> Enum.filter(&(&1 != ""))
  end

  defp host(value) do
    case URI.parse(value) do
      %URI{host: host} when is_binary(host) and host != "" -> host
      _other -> value
    end
  end

  defp codex_tool("item/commandExecution/requestApproval"), do: "bash"
  defp codex_tool("item/fileChange/requestApproval"), do: "edit"
  defp codex_tool("item/permissions/requestApproval"), do: "permissions"
  defp codex_tool(_method), do: "unknown"

  defp codex_kind("item/fileChange/requestApproval"), do: "file_change"
  defp codex_kind("item/permissions/requestApproval"), do: "permissions"
  defp codex_kind(_method), do: "sandbox_escalation"

  defp codex_mode("item/commandExecution/requestApproval"), do: :execute
  defp codex_mode(_method), do: :write

  defp codex_paths("item/fileChange/requestApproval", params) do
    changes = params["changes"] || params["files"] || []

    paths =
      case changes do
        list when is_list(list) -> Enum.map(list, &location_path/1)
        map when is_map(map) -> Map.keys(map)
        _other -> []
      end

    (paths ++ [params["path"], params["grantRoot"]])
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.uniq()
  end

  defp codex_paths(_method, params) do
    [params["grantRoot"], params["path"]]
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.uniq()
  end

  defp text(value) when is_binary(value), do: value
  defp text(value) when is_list(value), do: Enum.map_join(value, " ", &to_string/1)
  defp text(_value), do: nil

  defp field(source, key) when is_map(source), do: Map.get(source, key)
  defp field(_source, _key), do: nil
end
