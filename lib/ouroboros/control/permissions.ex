defmodule Ouroboros.Control.Permissions do
  @moduledoc """
  One permission engine, server-side, consulted before any human is asked.

  Every approval this runtime can intercept passes through `evaluate/1` first. A stored
  rule that says `allow` answers the provider immediately; a rule that says `deny`
  refuses it with the rule named; anything else becomes the approval prompt that exists
  today. The point is not to prompt less for its own sake — it is that 98.9% of analysed
  Claude Code configurations had zero deny rules because prompting for everything trains
  people to stop reading ([AGENT_EXPERIENCE §2.5](../../../docs/AGENT_EXPERIENCE.md)).
  A prompt that survives is one that was worth showing.

  ## The three calls

      evaluate(request) :: {:allow, rule_ref} | {:deny, rule_ref} | {:ask, reason}
      record(decision_id, answer) :: :ok | {:error, term()}
      remember(principal, pattern, decision, scope) :: {:ok, rule} | {:error, term()}

  `evaluate/1` never raises and never blocks on anything unbounded. `record/2` writes a
  human's answer to the ledger. `remember/4` is "don't ask again": it turns one answer
  into a rule at the scope the human picked.

  ## Scopes, highest authority first

  | scope | where it lives | who writes it |
  |---|---|---|
  | `:node` | `config :ouroboros, :permissions` | the operator, in configuration |
  | `:user` | the node's data directory | `permissions.add`, `remember/4` |
  | `:workspace` | the node's data directory, keyed by canonical root | the same |
  | `:session` | the same store, keyed by session id | `remember/4` from an answer |

  Workspace rules live in the **data directory, not the repository**, and that is
  deliberate. A repository that shipped its own allow rules would be a repository that
  grants itself permissions on every machine that clones it — Kiro's reasoning, and
  Claude Code's for gating project allow rules on workspace trust (R3 §8d, "trusting
  repo-supplied config"). The data directory is chosen over `$XDG_CONFIG_HOME` for the
  same reason every other durable store here uses it: it is the directory this node
  already claims exclusively at boot, syncs writes into, and refuses to run without.

  Decision order is `Ouroboros.Control.Permissions.Rules`': any `deny` wins, then `ask`,
  then `allow`, with scope breaking ties **within** a rank only.

  ## Fail-closed, in the two directions that matter

  Storage that cannot answer degrades to `{:ask, :authority_unavailable}` for anything a
  stored rule would have allowed, while protected paths and node-configured denies still
  deny — those are computed from configuration and the request, with no store involved.
  A rule whose checkpoint fails is not applied in memory and not reported as added, so a
  storage fault narrows authority rather than widening it. And an `:allow` whose ledger
  entry cannot be written is downgraded to `:ask`: an approval nobody can later account
  for has not been granted.

  ## What this is not

  It is not a sandbox. It decides what the runtime *asks* a provider to do at the two
  seams where a provider asks first — `Dialect.ACP.approval_request/2` and
  `Dialect.Codex.approval_request/2` — and nothing else. A vendor CLI that runs a tool
  without asking runs it. There is no classifier here; `auto` mode is a later slice on
  top of this engine and never a replacement for rules (D5). Command substitution,
  `eval`, and `sh -c` defeat prefix matching by construction, which is why the honest
  posture is an allowlist plus protected paths rather than a denylist (R3 §8d).

  This module lives under `Ouroboros.Control.` for the same reason `Control.Grants` does:
  the prefix is in `Ouroboros.Upgrade.Verifier`'s protected set, so the fast patch lane
  refuses an artifact that would replace the engine deciding what code may do. A runtime
  that can author code must not be able to author its own permissions away.
  """

  use GenServer

  require Logger

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Permissions.{Pattern, Request, Rule, Rules}

  @store_key {:ouroboros, :control_permissions, 1}
  @checkpoint_version 1
  @default_rule_limit 500
  @stored_scopes [:user, :workspace, :session]
  @call_timeout 5_000

  @type server :: GenServer.server()
  @type rule_ref :: %{scope: atom(), id: String.t(), pattern: String.t()}
  @type outcome :: {:allow, rule_ref()} | {:deny, rule_ref()} | {:ask, atom()}
  @type answer :: %{
          required(:decision) => :approve | :deny,
          optional(:scope) => :once | :session | :always,
          optional(:actor) => :rule | :human | :classifier,
          optional(:rule_ref) => term(),
          optional(:reason) => String.t() | nil
        }

  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Decides one tool call before a human is asked.

  The request is a map:

      %{
        principal: %{session_id: String.t(), provider: atom(), node: node()},
        tool: String.t(),          # "bash", "edit", "mcp:<server>:<tool>", or the vendor's own name
        command: String.t() | nil, # the shell command line when the tool is a shell
        paths: [String.t()],       # paths the call reads or writes
        mode: :read | :write | :execute | :network,
        domains: [String.t()],     # for network tools
        context: map()             # free-form, content-minimised — never the prompt
      }

  Every `:allow` and `:deny` reached by a rule is written to `Ouroboros.Agent.EffectLedger`
  as a `:permission` effect before it is returned. An `:allow` whose entry cannot be
  written is returned as `{:ask, :unrecordable}`; a `:deny` is returned regardless,
  because refusing without an audit entry is still refusing.

  Never raises. Never returns anything but the three shapes.
  """
  @spec evaluate(map() | keyword(), server()) :: outcome()
  def evaluate(request, server \\ __MODULE__) do
    normalized = Request.new(request)
    node_outcome = Rules.decide(normalized, node_rules())

    case node_outcome do
      # Protected paths and operator denies need no store, so they answer even when the
      # authority is down.
      {:deny, _ref} = deny ->
        record_outcome(deny, normalized)

      _other ->
        normalized |> stored_outcome(node_outcome, server) |> record_outcome(normalized)
    end
  rescue
    error ->
      Logger.warning("permission evaluation failed: #{Exception.message(error)}")
      {:ask, :authority_unavailable}
  catch
    _kind, _reason -> {:ask, :authority_unavailable}
  end

  @doc """
  Records one answer — usually a human's — in the effect ledger.

  `decision_id` is caller-minted and stable, so a retry after a lost acknowledgement
  records the same entry rather than a second one. The seams use
  `"<session id>:<provider request id>"`.

  Two optional keys beyond the contract's four attribute the entry: `:request`, the same
  map `evaluate/1` took, and `:principal` on its own when the call is all that is left.
  Without either, the entry is recorded against `"unattributed"` rather than not at all —
  an audit that drops what it cannot attribute is worse than one that says so.
  """
  @spec record(String.t(), answer()) :: :ok | {:error, term()}
  def record(decision_id, answer)
      when is_binary(decision_id) and decision_id != "" and is_map(answer) do
    ledger_write(decision_id, answer, answered_request(answer))
  end

  def record(_decision_id, _answer), do: {:error, :invalid_permission_record}

  defp answered_request(answer) do
    cond do
      match?(%Request{}, Map.get(answer, :request)) ->
        Map.get(answer, :request)

      is_map(Map.get(answer, :request)) ->
        Request.new(Map.get(answer, :request))

      is_map(Map.get(answer, :principal)) ->
        Request.new(%{principal: Map.get(answer, :principal)})

      true ->
        nil
    end
  end

  @doc """
  Turns one answer into a rule: "don't ask again".

  `scope` is `:user`, `:workspace`, or `:session`. `:node` is refused — operator
  configuration is not something a session's answer may write. A `:workspace` rule needs
  the principal to carry a workspace root, and a `:session` rule needs a session id.
  """
  @spec remember(map(), String.t() | Pattern.t(), :allow | :deny, atom(), server()) ::
          {:ok, map()} | {:error, term()}
  def remember(principal, pattern, decision, scope, server \\ __MODULE__)

  def remember(principal, pattern, decision, scope, server)
      when is_map(principal) and decision in [:allow, :deny] and scope in @stored_scopes do
    attrs = %{
      scope: scope,
      decision: decision,
      pattern: pattern,
      workspace: Map.get(principal, :workspace) || Map.get(principal, "workspace"),
      session_id: Map.get(principal, :session_id) || Map.get(principal, "session_id")
    }

    add(attrs, server)
  end

  def remember(_principal, _pattern, _decision, scope, _server) when scope == :node,
    do: {:error, :node_scope_is_operator_configuration}

  def remember(_principal, _pattern, _decision, _scope, _server),
    do: {:error, :invalid_permission_rule}

  @doc "Adds one rule at a stored scope. The gateway's `permissions.add`."
  @spec add(map() | keyword(), server()) :: {:ok, map()} | {:error, term()}
  def add(attrs, server \\ __MODULE__) do
    with {:ok, rule} <- build(attrs) do
      safe_call(server, {:add, rule})
    end
  end

  @doc "Removes one rule by id. The gateway's `permissions.remove`."
  @spec remove(atom(), String.t(), server()) :: :ok | {:error, term()}
  def remove(scope, id, server \\ __MODULE__)

  def remove(scope, id, server) when scope in @stored_scopes and is_binary(id) and id != "",
    do: safe_call(server, {:remove, scope, id})

  def remove(:node, _id, _server), do: {:error, :node_scope_is_operator_configuration}
  def remove(_scope, _id, _server), do: {:error, :invalid_permission_rule}

  @doc """
  Lists rules, newest first.

  Filters are `:scope` and `:workspace`. Node rules come from configuration and are
  included whenever the scope filter admits them, so an operator reading this list sees
  everything that can decide, not only what is stored.
  """
  @spec list(keyword() | map(), server()) :: {:ok, [map()]} | {:error, term()}
  def list(filters \\ [], server \\ __MODULE__) do
    filters = if is_list(filters), do: Map.new(filters), else: filters

    with {:ok, scope} <- filter_scope(Map.get(filters, :scope)),
         {:ok, workspace} <- filter_workspace(Map.get(filters, :workspace)),
         {:ok, stored} <- safe_call(server, :rules) do
      rules =
        (node_rules() ++ stored)
        |> Enum.filter(&(is_nil(scope) or &1.scope == scope))
        |> Enum.filter(&(is_nil(workspace) or &1.workspace == workspace))
        |> Enum.sort_by(
          &{Enum.find_index(Rule.scopes(), fn s -> s == &1.scope end), &1.created_at}
        )
        |> Enum.map(&Rule.public/1)

      {:ok, rules}
    end
  end

  @doc "Drops every rule a session remembered. Session rules die with the session."
  @spec forget_session(String.t(), server()) :: :ok | {:error, term()}
  def forget_session(session_id, server \\ __MODULE__)

  def forget_session(session_id, server) when is_binary(session_id) and session_id != "",
    do: safe_call(server, {:forget_session, session_id})

  def forget_session(_session_id, _server), do: {:error, :invalid_session}

  @doc "Bounded sizing, durability, and the protected-path list."
  @spec status(server()) :: map()
  def status(server \\ __MODULE__) do
    case safe_call(server, :status) do
      %{} = status ->
        Map.put(status, :protected_paths, Rules.protected_paths())

      {:error, reason} ->
        %{
          durability: :unavailable,
          error: reason,
          node_rules: length(node_rules()),
          protected_paths: Rules.protected_paths()
        }
    end
  end

  @doc """
  The rule an operator would write to stop being asked about this request again.

  Pure and content-minimised in the sense that matters here: it is derived from the
  command's leading words or the path's directory, never from a prompt. `nil` when there
  is nothing honest to suggest.
  """
  @spec suggest(map() | keyword() | Request.t()) :: String.t() | nil
  def suggest(%Request{} = request) do
    cond do
      is_binary(request.command) ->
        suggest_command(request.command)

      request.mode == :network and request.domains != [] ->
        "WebFetch(domain:#{hd(request.domains)})"

      request.mode == :read and request.paths != [] ->
        "Read(#{suggest_glob(hd(request.paths))})"

      request.write_paths != [] ->
        "Edit(#{suggest_glob(hd(request.write_paths))})"

      request.tool != "unknown" ->
        "Tool(#{request.tool})"

      true ->
        nil
    end
  rescue
    _error -> nil
  end

  def suggest(request), do: request |> Request.new() |> suggest()

  @doc false
  def checkpoint_key, do: @store_key

  @doc false
  @spec node_rules() :: [Rule.t()]
  def node_rules do
    :ouroboros
    |> Application.get_env(:permissions, [])
    |> configured_rules()
  end

  # ── server ─────────────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    with {:ok, storage} <- storage_config(opts),
         {:ok, adapter, adapter_opts} <- normalize_storage(storage),
         {:ok, limit} <- rule_limit(opts),
         {:ok, rules} <- load(adapter, adapter_opts) do
      {:ok,
       %{
         adapter: adapter,
         opts: adapter_opts,
         rules: rules,
         limit: limit,
         durability: durability_level(adapter)
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:rules, _from, state), do: {:reply, {:ok, Map.values(state.rules)}, state}

  def handle_call({:decide, request}, _from, state) do
    {:reply, Rules.decide(request, Map.values(state.rules)), state}
  end

  def handle_call({:add, rule}, _from, state) do
    cond do
      Map.has_key?(state.rules, rule.id) ->
        {:reply, {:ok, Rule.public(Map.fetch!(state.rules, rule.id))}, state}

      map_size(state.rules) >= state.limit ->
        {:reply, {:error, {:permission_rule_limit_reached, state.limit}}, state}

      true ->
        persist(Map.put(state.rules, rule.id, rule), {:ok, Rule.public(rule)}, state)
    end
  end

  def handle_call({:remove, scope, id}, _from, state) do
    case Map.fetch(state.rules, id) do
      {:ok, %Rule{scope: ^scope}} -> persist(Map.delete(state.rules, id), :ok, state)
      {:ok, %Rule{}} -> {:reply, {:error, {:permission_rule_scope_mismatch, id}}, state}
      :error -> {:reply, {:error, {:unknown_permission_rule, id}}, state}
    end
  end

  def handle_call({:forget_session, session_id}, _from, state) do
    remaining =
      state.rules
      |> Enum.reject(fn {_id, rule} ->
        rule.scope == :session and rule.session_id == session_id
      end)
      |> Map.new()

    if map_size(remaining) == map_size(state.rules),
      do: {:reply, :ok, state},
      else: persist(remaining, :ok, state)
  end

  def handle_call(:status, _from, state) do
    counts = state.rules |> Map.values() |> Enum.frequencies_by(& &1.scope)

    {:reply,
     %{
       durability: state.durability,
       limit: state.limit,
       stored: map_size(state.rules),
       node_rules: length(node_rules()),
       by_scope: Map.new(Rule.scopes(), &{&1, Map.get(counts, &1, 0)})
     }, state}
  end

  # A rule is spent after this call returns, so a failed checkpoint leaves memory alone:
  # the caller holds nothing it could act on. A failed *removal* leaves the rule standing
  # for the mirror-image reason `Control.Grants` states — a rule this node could not
  # durably forget would come back at the next boot.
  defp persist(rules, reply, state) do
    case adapter_call(state.adapter, :put_checkpoint, [@store_key, checkpoint(rules), state.opts]) do
      :ok -> {:reply, reply, %{state | rules: rules}}
      {:error, reason} -> {:reply, {:error, {:permission_checkpoint_failed, reason}}, state}
      other -> {:reply, {:error, {:invalid_permission_storage_response, other}}, state}
    end
  end

  # ── evaluation ─────────────────────────────────────────────────────────────────────

  defp stored_outcome(request, node_outcome, server) do
    case safe_call(server, {:decide, request}) do
      {:error, _reason} ->
        # The store is the only thing that could have held a stricter rule, so nothing it
        # would have allowed can be allowed now.
        case node_outcome do
          {:allow, _ref} -> {:ask, :authority_unavailable}
          {:ask, _reason} -> {:ask, :authority_unavailable}
          other -> other
        end

      stored ->
        combine(node_outcome, stored)
    end
  end

  # Both halves already answered under the same rank-then-scope order; combining them is
  # taking the stricter, with node winning an exact tie because it is the higher scope.
  defp combine(node_outcome, stored_outcome) do
    if rank(node_outcome) <= rank(stored_outcome), do: node_outcome, else: stored_outcome
  end

  # The same deny → ask → allow order `Rules` applies inside one rule set, with one
  # addition: `{:ask, :no_rule}` means *nothing said anything*, so it is weaker than an
  # allow rather than stronger. Reading it as an ask would mean an operator's allow could
  # never take effect, because the store always has nothing to say about most calls.
  defp rank({:deny, _ref}), do: 0
  defp rank({:ask, :rule}), do: 1
  defp rank({:allow, _ref}), do: 2
  defp rank({:ask, _reason}), do: 3

  defp record_outcome({:allow, ref} = outcome, request) do
    case ledger_write(evaluation_id(request, ref), rule_answer(:approve, ref), request) do
      :ok ->
        outcome

      {:error, reason} ->
        Logger.warning("permission allow not recorded, downgrading to ask: #{inspect(reason)}")
        {:ask, :unrecordable}
    end
  end

  defp record_outcome({:deny, ref} = outcome, request) do
    _ = ledger_write(evaluation_id(request, ref), rule_answer(:deny, ref), request)
    outcome
  end

  defp record_outcome(outcome, _request), do: outcome

  defp rule_answer(decision, ref) do
    %{decision: decision, scope: :once, actor: :rule, rule_ref: ref, reason: nil}
  end

  defp evaluation_id(request, ref) do
    digest =
      [
        request.principal.session_id || "",
        request.tool,
        request.command || "",
        Enum.join(request.paths, ":"),
        to_string(request.mode),
        ref[:id] || ""
      ]
      |> Enum.join("\n")

    "perm-" <>
      (:crypto.hash(:sha256, digest) |> Base.encode16(case: :lower) |> binary_part(0, 32))
  end

  # ── ledger ─────────────────────────────────────────────────────────────────────────

  defp ledger_write(decision_id, answer, request) do
    decision = Map.get(answer, :decision)
    ref = Map.get(answer, :rule_ref)

    attrs = %{
      id: decision_id,
      effect: :permission,
      principal: principal_id(request),
      attempt: attempt(request),
      authority: %{decision: decision, reason: Map.get(answer, :reason)},
      cause: %{signal_id: decision_id, signal_type: "permission"},
      result: %{
        decision: decision,
        scope: Map.get(answer, :scope, :once),
        actor: Map.get(answer, :actor, :human),
        rule_id: ref_id(ref)
      }
    }

    write =
      if decision == :deny,
        do: EffectLedger.record_denied(Map.put(attrs, :error, :permission_denied), ledger()),
        else: EffectLedger.record_settled(attrs, ledger())

    case write do
      {:ok, _entry, _disposition} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  # Where permission decisions are recorded. `Ouroboros.Agent.EffectLedger` is the answer;
  # naming it in configuration is what lets a test point the engine at a ledger it can
  # take away, which is the only way to observe an unrecordable allow becoming an ask.
  defp ledger, do: Application.get_env(:ouroboros, :permissions_ledger, EffectLedger)

  defp principal_id(%Request{principal: %{session_id: session_id}}) when is_binary(session_id),
    do: session_id

  defp principal_id(_request), do: "unattributed"

  defp attempt(%Request{} = request) do
    %{
      tool: request.tool,
      mode: request.mode,
      provider: request.principal.provider,
      fingerprint: fingerprint(request)
    }
  end

  defp attempt(_request), do: %{tool: "unknown", mode: :write, provider: nil, fingerprint: nil}

  # The command line and the paths never reach the ledger. Their digest does, which is
  # enough to prove two entries were the same decision and nothing else.
  defp fingerprint(%Request{} = request) do
    material = [request.command || "" | request.paths ++ request.domains] |> Enum.join("\n")

    %{
      sha256: :crypto.hash(:sha256, material) |> Base.encode16(case: :lower),
      bytes: byte_size(material)
    }
  end

  defp ref_id(%{id: id}) when is_binary(id), do: id
  defp ref_id(_ref), do: nil

  # ── configuration and storage ──────────────────────────────────────────────────────

  defp configured_rules(entries) when is_list(entries) do
    entries
    |> Enum.with_index()
    |> Enum.flat_map(fn {entry, index} -> configured_rule(entry, index) end)
  end

  defp configured_rules(_entries), do: []

  defp configured_rule({pattern, decision}, index),
    do: configured_rule({pattern, decision, nil}, index)

  defp configured_rule({pattern, decision, workspace}, index) do
    case Rule.new(%{
           scope: :node,
           decision: decision,
           pattern: pattern,
           workspace: workspace,
           created_at: "0000-00-#{String.pad_leading(to_string(index), 2, "0")}"
         }) do
      {:ok, rule} ->
        [rule]

      {:error, reason} ->
        Logger.warning(
          "ignoring invalid node permission rule #{inspect(pattern)}: #{inspect(reason)}"
        )

        []
    end
  end

  defp configured_rule(other, _index) do
    Logger.warning("ignoring malformed node permission rule #{inspect(other)}")
    []
  end

  defp build(attrs) when is_list(attrs), do: attrs |> Map.new() |> build()

  defp build(attrs) when is_map(attrs) do
    case Map.get(attrs, :scope) do
      scope when scope in @stored_scopes -> Rule.new(attrs)
      :node -> {:error, :node_scope_is_operator_configuration}
      other -> {:error, {:unknown_permission_scope, other}}
    end
  end

  defp build(other), do: {:error, {:invalid_rule, other}}

  defp filter_scope(nil), do: {:ok, nil}

  defp filter_scope(scope) when is_atom(scope),
    do:
      if(scope in Rule.scopes(),
        do: {:ok, scope},
        else: {:error, {:unknown_permission_scope, scope}}
      )

  defp filter_scope(other), do: {:error, {:unknown_permission_scope, other}}

  defp filter_workspace(nil), do: {:ok, nil}

  defp filter_workspace(workspace) when is_binary(workspace) and workspace != "",
    do: {:ok, workspace}

  defp filter_workspace(other), do: {:error, {:invalid_workspace, other}}

  defp checkpoint(rules), do: %{version: @checkpoint_version, rules: rules}

  defp load(adapter, adapter_opts) do
    case adapter_call(adapter, :get_checkpoint, [@store_key, adapter_opts]) do
      :not_found ->
        {:ok, %{}}

      {:ok, %{version: @checkpoint_version, rules: rules}} when is_map(rules) ->
        if valid_rules?(rules),
          do: {:ok, rules},
          else: {:error, :invalid_permission_checkpoint}

      # A checkpoint this build cannot read is preserved, not overwritten, and never read
      # as "no rules" — that would silently widen what every session may do.
      {:ok, %{version: version}} ->
        {:error, {:unsupported_permission_checkpoint, version}}

      {:ok, _invalid} ->
        {:error, :invalid_permission_checkpoint}

      {:error, reason} ->
        {:error, {:permission_checkpoint_unreadable, reason}}

      other ->
        {:error, {:invalid_permission_storage_response, other}}
    end
  end

  defp valid_rules?(rules) do
    Enum.all?(rules, fn
      {id, %Rule{id: id} = rule} -> Rule.valid?(rule) and rule.scope in @stored_scopes
      _other -> false
    end)
  end

  defp storage_config(opts) do
    case Keyword.fetch(opts, :storage) do
      {:ok, storage} ->
        {:ok, storage}

      :error ->
        {:ok,
         Application.get_env(
           :ouroboros,
           :permissions_storage,
           {Jido.Storage.ETS, table: :ouroboros_permissions}
         )}
    end
  end

  defp normalize_storage(storage) do
    {adapter, adapter_opts} = Jido.Storage.normalize_storage(storage)
    {:ok, adapter, adapter_opts}
  rescue
    error -> {:error, {:invalid_permissions_storage, Exception.message(error)}}
  end

  defp rule_limit(opts) do
    limit =
      Keyword.get_lazy(opts, :limit, fn ->
        Application.get_env(:ouroboros, :permissions_limit, @default_rule_limit)
      end)

    if is_integer(limit) and limit >= 1,
      do: {:ok, limit},
      else: {:error, {:invalid_permissions_limit, limit}}
  end

  defp durability_level(Jido.Storage.ETS), do: :ephemeral_checkpoint
  defp durability_level(Ouroboros.Storage.DurableFile), do: :synced_checkpoint
  defp durability_level(_adapter), do: :durable_checkpoint

  defp adapter_call(adapter, function, arguments) do
    apply(adapter, function, arguments)
  rescue
    error -> {:error, {:adapter_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:adapter_failure, kind, inspect(reason)}}
  end

  defp safe_call(server, message) do
    GenServer.call(server, message, @call_timeout)
  catch
    :exit, reason -> {:error, {:permissions_unavailable, reason}}
  end

  # ── suggestions ────────────────────────────────────────────────────────────────────

  defp suggest_command(command) do
    alias Ouroboros.Control.Permissions.Shell

    case command |> Shell.split() |> List.first() do
      nil ->
        nil

      first ->
        case first |> Shell.strip_wrappers() |> Shell.tokens() do
          [] -> nil
          [executable] -> "Bash(#{base_name(executable)} *)"
          [executable, second | _rest] -> "Bash(#{suggest_words(executable, second)} *)"
        end
    end
  end

  # A subcommand is part of the identity of what is being run (`git commit`, `cargo test`),
  # so it stays; an option is an argument, and an argument-constraining suggestion is the
  # fragile kind this engine declines to propose.
  defp suggest_words(executable, second) do
    executable = base_name(executable)

    if Regex.match?(~r/\A[a-z][a-z0-9:_-]*\z/i, second),
      do: executable <> " " <> second,
      else: executable
  end

  defp suggest_glob(path), do: Path.dirname(path) <> "/**"

  defp base_name(token), do: token |> String.split("/") |> List.last()
end
