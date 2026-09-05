defmodule Ouroboros.Control.Permissions.Seam do
  @moduledoc """
  The ACP process boundary where a provider asks first and what the engine says there.

  `Dialect.ACP.approval_request/2` is the remaining pre-tool point for a vendor process.
  It runs inside `Session.Jsonl` and receives only the method and provider params; the
  native direct provider evaluates permissions in its own loop.

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

  ACP `session/request_permission` gives a `toolCall` with `kind`, `title`, `rawInput`,
  and `locations`; the command line is in `rawInput.command` and the paths in `locations`.
  It is mapped onto the request shape `Ouroboros.Control.Permissions.evaluate/1` takes.

  ## Which engine answers (W18, D27)

  `config :ouroboros, :permissions_engine`, the same node-level setting its three other
  readers hold — the native loop (`Ouroboros.Provider.Native.Permissions`), the interactive
  plane's external approvals (`Ouroboros.Interactive.Task.Approvals`) and the interactive
  shell (`Ouroboros.Interactive.Task.Shell`, through `Approvals.permissions_engine/2`) —
  and the same default, `Ouroboros.Control.Permissions`, when an operator has named
  nothing. One setting names the engine for all four, so a node configured with
  `Ouroboros.Wasm.PolicyEngine` is covered on the ACP lane too rather than on three
  seams out of four.

  The tolerance is `Approvals`', verbatim, because a decision seam that can crash is a
  session that can crash: `{:allow, ref}`, `{:deny, ref}` and `{:ask, reason}` pass
  through, an answer in none of those shapes is `:ask`, and an engine that raises or
  exits is `:ask` with the payload the dialect would have emitted anyway.

  **What that invariant is, stated precisely.** *No engine **failure** widens anything
  here*: every way of not answering — an unrecognised shape, an exception, an exit, an
  engine that is not loaded or does not export what C13 asks for — lands on the ask the
  human was always going to see. What an engine **does** answer is its own authority,
  exactly as it is on the other three seams: an `{:allow, ref}` is honoured, `ref` and
  all, and this seam adds no gate of its own on top of it. That is deliberate rather
  than an omission — a second gate here would be a rule an operator cannot see in either
  place — and it is why the bound that matters lives in the engine: `PolicyEngine` honours
  a component's `allow` only for the tools named in `:policy_allowable_tools`, empty by
  default (D20).

  `remember/4` and `forget_session/1` stay on `Control.Permissions` whatever engine is
  named: they are rule-store operations rather than decisions. C13 asks an engine for
  `evaluate/1`, `record/2` and `suggest/1` and for nothing else, and a "don't ask again"
  a human wrote belongs in the node's own store — an engine that wrapped the store would
  have to reimplement scopes, session forgetting and the gateway's `permissions.add` to
  be asked for it. The **pattern** a `:session` answer is written as is the store's own
  `Control.Permissions.suggest/1` for the same reason: that row is durable, and how wide a
  rule one human's "yes" creates is not something a named engine gets to widen from
  underneath. The engine's `suggest/1` phrases the `suggested_rule` hint on an ask, which
  is a string a client renders and nothing enforces.

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

  # All transports use the same configured-engine lookup and fail-closed verdicts.
  alias Ouroboros.Control.Permissions.Engine

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
  @spec decide(:acp, String.t(), map(), map()) :: verdict()
  def decide(dialect, method, params, payload) do
    bound = principal()
    request = request(dialect, method, params, bound)

    case evaluate(request) do
      {:allow, ref} -> {:allow, ref}
      {:deny, ref} -> {:deny, ref}
      {:ask, {:engine_error, _reason}} -> {:ask, payload}
      {:ask, _reason} -> {:ask, suggested(payload, request)}
    end
  rescue
    # The seam can only ever make a decision *narrower*. If it cannot make one at all,
    # the approval reaches the human exactly as it did before this module existed.
    # `Approvals`' two clauses, verbatim and each load-bearing: an exception is caught by
    # the `rescue`, an exit by the `catch`. A `throw` is not swallowed here, exactly as it
    # is not swallowed there — a thrown decision is a bug in an engine, not an answer.
    _exception -> {:ask, payload}
  catch
    :exit, _reason -> {:ask, payload}
  end

  @doc """
  Decides one service request the agent asked *this runtime* to perform.

  C4's second seam, and a different question from `decide/4`. There the provider is
  asking permission for something it will do itself; here an ACP agent has called the
  client — `fs/write_text_file`, `terminal/create` — and Ouroboros is the process that
  will do it. That makes the classification the runtime's own rather than a reading of
  someone else's params, so the caller states it: `Ouroboros.Provider.Session.Service`
  knows the canonical path it resolved and the command line it is about to run, and
  passes both here already normalised.

  Classified as the ordinary tool it is, deliberately. A `terminal/create` is a shell
  execution and arrives as `tool: "bash"` with the command line, so a `Bash(…)` deny an
  operator wrote covers it — a service that classified itself as `Tool(terminal/create)`
  would be a documented way around every rule the operator already has. A write over an
  existing file is `tool: "edit"` and a write that creates one is `tool: "write"`, so
  `Edit(…)` and `Write(…)` each mean what they say.
  """
  @spec decide_service(:acp, map(), map()) :: verdict()
  def decide_service(dialect, fields, payload) do
    bound = principal()
    request = service_request(dialect, fields, bound)

    case evaluate(request) do
      {:allow, ref} -> {:allow, ref}
      {:deny, ref} -> {:deny, ref}
      {:ask, {:engine_error, _reason}} -> {:ask, payload}
      {:ask, _reason} -> {:ask, suggested(payload, request)}
    end
  rescue
    _exception -> {:ask, payload}
  catch
    :exit, _reason -> {:ask, payload}
  end

  @doc """
  Records a human's answer, and turns a session-scoped one into a rule.

  `stash` is the dialect's own approval stash, which carries the provider params the
  request was built from. `decision_id` is stable per session and provider request id, so
  a retried acknowledgement records once.

  A service stash carries the fields `decide_service/3` was asked with instead of the
  provider's params, because there is no provider request to re-read: rebuilding a
  `session/request_permission` shape from a `fs/write_text_file` frame would write a
  ledger entry describing something that never happened.
  """
  @spec answered(:acp, String.t(), map(), map()) :: :ok
  def answered(dialect, decision_id, %{service: fields} = stash, response)
      when is_map(fields) do
    record_answer(decision_id, service_request(dialect, fields, principal()), stash, response)
  end

  def answered(dialect, decision_id, stash, response) do
    bound = principal()
    params = Map.get(stash, :params) || %{}
    method = Map.get(stash, :method) || ""
    request = request(dialect, method, params, bound)
    record_answer(decision_id, request, stash, response)
  rescue
    _error -> :ok
  catch
    _kind, _reason -> :ok
  end

  defp record_answer(decision_id, request, _stash, response) do
    _ =
      record(decision_id, %{
        decision: response.decision,
        scope: response.scope,
        actor: :human,
        rule_ref: nil,
        reason: response.reason,
        request: request
      })

    _ = remember(response, request, principal())
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

  `Control.Permissions` whatever `:permissions_engine` names, because this drops rows from
  the rule store rather than deciding anything (C13); an engine that never held those rows
  has nothing to forget.
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

  @doc """
  A refusal reason that names the rule, for the provider and for the transcript.

  A `rule_ref` is whatever the engine returned. `Control.Permissions` returns the rule that
  matched; `Ouroboros.Wasm.PolicyEngine` returns a sentence it composed — the component's
  name and sha, the `[untrusted policy component]` label, and the component's own rule — so
  a binary is passed through rather than flattened into "a permission rule", which is what
  makes an ACP refusal **name the same rule** the native loop's `deny_message/2` names.
  The two sentences differ in wording and in bound — the native one reads "Refused:
  permission rule … denies … for this session." and is unbounded; this one reads
  "refused by …" and is clipped — because one is a tool result a model reads and the other
  is a JSON-RPC error a client renders.

  Bounded and stripped of control characters here as well as at the engine, because this
  string is written into a JSON-RPC error a vendor process reads, and how long somebody
  else's sentence may be is not a question to answer once.
  """
  @spec refusal(term()) :: String.t()
  def refusal(%{scope: scope, pattern: pattern}) when is_atom(scope) and is_binary(pattern),
    do: "refused by the #{scope}-scope permission rule #{stated(pattern)}"

  def refusal(rule) when is_binary(rule) and rule != "", do: "refused by " <> stated(rule)

  def refusal(_ref), do: "refused by a permission rule"

  # Graphemes, not bytes, and `Ouroboros.Wasm.PolicyEngine`'s own character class, so
  # "the same class here as at the engine" is a fact rather than a near-miss: `\p{C}` alone
  # leaves U+2028 and U+2029, which end a line in a JSON-RPC error a client renders.
  @max_refusal_graphemes 400

  # Both callers are guarded on `is_binary`, which is also what keeps `refusal/1` total: a
  # malformed ref falls to the catch-all rather than reaching `to_string/1` on the way to a
  # frame, where an exception would take the session rather than the request.
  defp stated(rule) when is_binary(rule) do
    rule
    |> String.replace(~r/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u, " ")
    |> String.slice(0, @max_refusal_graphemes)
  end

  # A "don't ask again" answer is exactly a rule the human just wrote by hand. `:once`
  # writes nothing, because that is what once means.
  #
  # **The pattern is the store's, not the engine's, and that is the whole of it.** This
  # writes a durable `:allow` row into `Control.Permissions`, so what it writes has to be
  # phrased in the grammar of the store that will match it — and an engine an operator
  # named is not the authority on how wide a rule one human's "yes" creates. An engine
  # whose `suggest/1` answered `Bash(*)` would otherwise turn a single approval of
  # `ls -la` into a session-wide allow for every shell command, which is a widening this
  # seam has no business performing. The engine's suggestion is a *hint* on the way out
  # (`suggested/2`); the row is the store's.
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
    case suggest(request) do
      pattern when is_binary(pattern) and pattern != "" ->
        Map.put(payload, "suggested_rule", pattern)

      _nothing_to_suggest ->
        payload
    end
  end

  # ── the engine (C13, D27) ──────────────────────────────────────────────────────────
  #
  # `Ouroboros.Interactive.Task.Approvals`' tolerance, verbatim: three shapes pass, an
  # answer in none of them is an ask, and a raise or an exit is an ask. The rescue and
  # catch live in `decide/4` and `decide_service/3`, where the payload the dialect would
  # have emitted is still in hand — the answer to an engine that failed is the approval
  # the human was always going to see, unannotated.

  defp evaluate(request), do: Engine.evaluate(request)
  defp record(decision_id, answer), do: Engine.record(decision_id, answer)
  defp suggest(request), do: Engine.suggest(request)

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

  # The caller already normalised this one, so nothing is inferred here: `tool`, `mode`,
  # `command` and `paths` are what `Session.Service` resolved, and only the principal and
  # the workspace are added. `method` travels in the context so the ledger row says which
  # client service was asked for.
  defp service_request(_dialect, fields, bound) do
    base(bound)
    |> Map.merge(%{
      tool: to_string(Map.get(fields, :tool) || "unknown"),
      command: text(Map.get(fields, :command)),
      paths: Enum.filter(List.wrap(Map.get(fields, :paths)), &(is_binary(&1) and &1 != "")),
      mode: Map.get(fields, :mode) || :write,
      domains: [],
      context: context(bound, %{"kind" => "acp_service", "method" => Map.get(fields, :method)})
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

  defp text(value) when is_binary(value), do: value
  defp text(value) when is_list(value), do: Enum.map_join(value, " ", &to_string/1)
  defp text(_value), do: nil

  defp field(source, key) when is_map(source), do: Map.get(source, key)
  defp field(_source, _key), do: nil
end
