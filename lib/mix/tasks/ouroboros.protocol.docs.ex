defmodule Mix.Tasks.Ouroboros.Protocol.Docs do
  @shortdoc "Regenerates docs/PROTOCOL.md from the method table and the golden fixtures"

  @moduledoc """
  Writes `docs/PROTOCOL.md` — the generated reference for the gateway wire protocol.

      mix ouroboros.protocol.docs

  ## Why this task exists

  There are two descriptions of this protocol that a person can read. `docs/TUI.md` §2 is
  the narrative: why the framing is what it is, what a client is expected to do about a
  pruned cursor, which honest limits the design accepted. It is written by hand and it is
  meant to be. This file is the other one — the exhaustive per-method reference — and a
  reference maintained by hand is a reference that is wrong within a release.

  So it is generated, from three sources and no fourth:

    * `Ouroboros.Gateway.Methods.table/0` — the scope, the ceiling, and the
      outcome admission of every method this build serves.
    * `Ouroboros.Gateway.Methods.params/0` — the parameter contract, which is held
      equal to the validators in `Ouroboros.Gateway.Methods` by
      `Ouroboros.Gateway.ProtocolDocsTest` parsing that module's own source.
    * `test/support/gateway_golden/*.json` — the pinned frames, embedded whole under the
      method or notification they answer.

  Nothing in the output is prose about behaviour that the code does not prove. Where a
  fact belongs to the narrative rather than to the table, the generated text says so and
  links to `docs/TUI.md` instead of paraphrasing it.

  ## Determinism

  Regenerating on another machine on another day writes the same bytes: the task reads no
  clock, no node name, and no configured value. The dynamic vocabularies it does read —
  `Ouroboros.CodeIntel.operations/0`, `Ouroboros.Agent.EffectLedger.effects/0` and
  `statuses/0`, and the ledger's own query bounds — are static per build, and reading them
  is the point: a document that stated a narrower vocabulary than the runtime accepts
  would be a document a client could be refused for believing.

  `Ouroboros.Gateway.ProtocolDocsTest` regenerates and compares byte for byte, so a
  gateway change that alters the surface fails the suite until this task is run.

  ## Two maps that force a decision rather than a silent omission

  `@fixture_owners` places every golden fixture, and `@code_glosses` names every protocol
  error. Both raise when the runtime grows a member they do not cover, because a fixture
  quietly missing from the reference and a fixture that was never written are the same
  thing to a client author.
  """

  use Mix.Task

  alias Mix.Tasks.Ouroboros.Gateway.Golden
  alias Ouroboros.Gateway.Methods

  @path "docs/PROTOCOL.md"

  # The five verbs `invoke/2` never sees: the four subscription verbs, because both planes
  # register the *calling* process as the subscriber, and `runtime.shutdown`, because it
  # needs the listener configuration and the socket the acknowledgement must reach.
  # `hello` is a sixth for the same reason — it owns the socket a failed handshake closes.
  # `Ouroboros.Gateway.ProtocolDocsTest` proves this list is exactly the set of table
  # methods with no `invoke/2` clause.
  @connection_answered ~w(
    hello
    interactive.subscribe
    interactive.unsubscribe
    coding.subscribe
    coding.unsubscribe
    runtime.shutdown
  )

  # Where each pinned frame belongs in the document. A fixture the task cannot place is a
  # hard failure rather than a fixture the reference silently drops.
  #
  # This map places the frames that pin the *envelope*, each under the method or
  # notification it answers. The transcript corpus is placed by `transcript_owners/0`
  # instead: it is one frame per event payload rather than one per verb, every entry would
  # otherwise have to be spelled out twice, and the gloss that says what each one pins is
  # already written beside the payload in `Golden.transcript_corpus/0`. `fixture_owners/0`
  # is the union, and `check_fixtures!/0` still refuses a fixture neither of them names.
  @fixture_owners %{
    "hello_result" => {:method, "hello"},
    "runtime_status_result" => {:method, "runtime.status"},
    "interactive_event_detail_result" => {:method, "interactive.event_detail"},
    "coding_event_detail_result" => {:method, "coding.event_detail"},
    "code_intel_diagnostics_result" => {:method, "code_intel.diagnostics"},
    "interactive_journal_result" => {:method, "interactive.journal"},
    "ledger_list_result" => {:method, "ledger.list"},
    "ledger_export_result" => {:method, "ledger.export"},
    "mcp_list_result" => {:method, "mcp.list"},
    "workspace_browse_result" => {:method, "workspace.browse"},
    "interactive_event_notification" => {:notification, "interactive.event"},
    "interactive_event_excerpt_notification" => {:notification, "interactive.event"},
    "coding_event_notification" => {:notification, "coding.event"},
    "stream_lagged_notification" => {:notification, "stream.lagged"},
    "stream_ended_notification" => {:notification, "stream.ended"},
    "error_unauthenticated" => {:error, :unauthenticated},
    "error_protocol_mismatch" => {:error, :protocol_mismatch},
    "error_scope_denied" => {:error, :scope_denied},
    "error_upstream_timeout_unknown" => {:error, :upstream_timeout},
    "error_cursor_pruned" => {:error, :upstream_error},
    "error_not_found" => {:error, :not_found},
    "error_invalid_request" => {:error, :invalid_request}
  }

  # One clause each, for the codes `Ouroboros.Gateway.Methods.codes/0` names. The task
  # raises on a code with no gloss, so a new error cannot reach a client undocumented.
  @code_glosses %{
    parse_error: "the line was not JSON",
    invalid_request: "the frame was JSON but not a request this subset accepts",
    method_not_found: "this build does not serve that method; `hello.methods` is the list",
    invalid_params: "a parameter was missing, mistyped, or outside a closed envelope",
    unauthenticated:
      "a frame arrived before a successful `hello`, or `hello` presented the wrong token",
    protocol_mismatch: "the client asked for a protocol version this gateway does not speak",
    scope_denied: "the method mutates the runtime and this listener was started at `read` scope",
    unavailable: "the plane that answers is not running or not configured on the target node",
    upstream_timeout: "the handler outlived this method's ceiling and was killed",
    upstream_error: "the plane answered with a failure, carried in `data`",
    not_found: "the record exists nowhere on the node that was asked"
  }

  # A reading order rather than an alphabet. A band this list does not name is appended
  # alphabetically, so a new band appears in the reference the day it appears in the table.
  @band_order ~w(
    handshake runtime fleet account agents interactive coding teams
    plans control permissions grants code_intel ledger workspace capabilities
    upgrade signing
  )

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.config")
    File.write!(@path, document())
    Mix.shell().info("wrote #{@path}")
  end

  @doc "Where the generated reference lives."
  @spec path() :: Path.t()
  def path, do: @path

  @doc """
  The whole document, as the bytes the file holds.

  Public because the drift test regenerates through this function and compares; a test
  that re-read the file it was checking would prove only that the file equals itself.
  """
  @spec document() :: binary()
  def document do
    body = IO.iodata_to_binary(body())
    IO.iodata_to_binary([header(body), body])
  end

  @doc "Every golden fixture and the place this document gives it."
  @spec fixture_owners() :: %{String.t() => {atom(), term()}}
  def fixture_owners, do: Map.merge(@fixture_owners, transcript_owners())

  defp transcript_owners do
    Map.new(Golden.transcript_corpus(), fn {name, gloss, _plane, _sequence, _type, _payload,
                                            _fields} ->
      {name, {:transcript, gloss}}
    end)
  end

  @doc "The methods answered by `Ouroboros.Gateway.Conn` rather than by `Methods.invoke/2`."
  @spec connection_answered() :: [String.t()]
  def connection_answered, do: @connection_answered

  # ---------------------------------------------------------------------------
  # The document
  # ---------------------------------------------------------------------------

  defp header(body) do
    digest = :sha256 |> :crypto.hash(body) |> Base.encode16(case: :lower) |> binary_part(0, 16)

    """
    <!-- Generated by `mix ouroboros.protocol.docs`. Do not edit by hand. -->

    # The Ouroboros gateway protocol

    Generated by `mix ouroboros.protocol.docs` from `Ouroboros.Gateway.Methods` and
    `test/support/gateway_golden/` — **do not edit by hand**. `mix test` regenerates this
    file and fails on any difference, so an edit made here is an edit the next test run
    rejects.

    Integrity anchor: `sha256:#{digest}` over everything below the rule that follows. A git
    commit sha is deliberately not embedded — this file is committed alongside the code it
    is generated from, and no commit can name itself before it exists. The digest and the
    drift test are what make the claim checkable instead of decorative.

    ---
    """
  end

  defp body do
    check_fixtures!()

    [
      contents(),
      connection_section(),
      errors_section(),
      notifications_section(),
      transcript_section(),
      methods_section(),
      limits_section()
    ]
  end

  defp contents do
    band_lines =
      Enum.map(bands(), fn band ->
        ["  - [", band, "](#", slug(band), ")\n"]
      end)

    [
      "\n## Contents\n\n",
      "- [How a connection works](#how-a-connection-works)\n",
      "- [Errors](#errors)\n",
      "- [Notifications](#notifications)\n",
      "- [Transcript payloads](#transcript-payloads)\n",
      "- [Methods](#methods)\n",
      band_lines,
      "- [What this is not](#what-this-is-not)\n"
    ]
  end

  # ---------------------------------------------------------------------------

  defp connection_section do
    entry = Map.fetch!(Methods.table(), "hello")
    protocol = fixture_json("hello_result")["result"]["protocol"]
    reads = Enum.count(Methods.table(), fn {_name, e} -> e.scope == :read end)
    operates = map_size(Methods.table()) - reads

    ceilings =
      Methods.table()
      |> Enum.group_by(fn {_name, e} -> e.timeout end, fn {name, _e} -> name end)
      |> Enum.sort_by(fn {timeout, names} -> {-length(names), timeout} end)
      |> Enum.map(fn {timeout, names} ->
        which =
          if length(names) > 8,
            do: "named in the per-band tables below",
            else: names |> Enum.sort() |> Enum.map(&["`", &1, "`"]) |> Enum.intersperse(", ")

        ["| `", duration(timeout), "` | ", Integer.to_string(length(names)), " | ", which, " |\n"]
      end)

    [
      """

      ## How a connection works

      Line-delimited JSON-RPC 2.0 over a loopback TCP socket: one JSON object per
      `\\n`-terminated line, no batches. Requests are `{jsonrpc, id, method, params}`,
      responses `{jsonrpc, id, result | error}`, and server notifications
      `{jsonrpc, method, params}` with no `id`. `params` is an object or absent — never an
      array, because a positional calling convention would be a second contract to keep
      correct in two languages. Every request carries an `id`: there are no client
      notifications, and a request with nowhere to send an answer is one whose fate the
      client cannot learn.

      The protocol version is the integer **#{protocol}**, as the `hello` fixture below
      pins it. The first frame on a connection must be `hello`; anything else is `-32001`
      and the socket closes, and a handshake not completed within
      **#{duration(entry.timeout)}** closes it too. `hello.methods` is the feature gate and
      the only one — a client decides whether an optional verb exists by membership in that
      list, never by trying it and reading the error. The list does not encode scope: a
      `read` listener still advertises the `operate` verbs it will refuse with `-32003`,
      because hiding them would make a deliberately less-authorized listener look like an
      older build.

      This build serves **#{map_size(Methods.table())}** methods: #{reads} at `read` scope
      and #{operates} at `operate`. Scope is the listener's, set once at start
      (`OUROBOROS_GATEWAY_SCOPE`); `runtime.shutdown` needs one permission beyond it.

      Every handler except the #{length(@connection_answered)} answered by the connection
      itself runs in a supervised task under the ceiling its table entry names. A handler
      that outlives its ceiling is killed and the request is answered `-32005`.

      **The token.** `hello.token` is compared against the listener's own by SHA-256 digest
      — hashing first makes the two lengths equal, so the comparison can neither raise nor
      leak one. Where that token comes from is listener configuration rather than protocol:
      a `0600` file named by `OUROBOROS_GATEWAY_TOKEN_FILE`, or `OUROBOROS_GATEWAY_TOKEN`
      for a development loop.

      **Resync turns on `sequence`.** Every event carries one, and it is the cursor the
      whole streaming contract uses. `replay` and `subscribe` take an *exclusive* cursor, so
      a window begins at the sequence after the one named, and `interactive.event_detail`
      is that window narrowed to one. `stream.lagged` says how many event frames were
      dropped and the newest sequence among them, which is how far ahead the session had
      run. A cursor below what a session still retains is refused with `-32006` carrying
      `{"reason": "cursor_pruned", "floor": N}` — the one error whose `data` a client
      branches on rather than displays, and it is pinned below. What a client should *do*
      about each of the three is [docs/TUI.md §2.5](TUI.md).

      | ceiling | methods | which |
      |---|---|---|
      """,
      ceilings,
      """

      `hello`'s entry is the one that does not describe a task ceiling: the handshake is
      answered by the connection and never runs in a task, so its number is the deadline by
      which the handshake must have completed. `Ouroboros.Gateway.Conn` reads it from the
      same table, so the number a client is told and the number enforced cannot drift apart.

      Why the framing is the way it is, what a client should *do* about a lagged stream or
      a pruned cursor, and the honest limits the design accepted are narrative rather than
      table, and they live in [docs/TUI.md §2](TUI.md) — §2.3 for the handshake and the
      error vocabulary, §2.5 for event streaming and resync, §2.6 for backpressure, §2.7
      for the wire encoder and its byte caps. This document does not paraphrase them.
      """
    ]
  end

  # ---------------------------------------------------------------------------

  defp errors_section do
    glosses = check_glosses!()

    rows =
      Methods.codes()
      |> Enum.sort_by(fn {_name, code} -> code end)
      |> Enum.map(fn {name, code} ->
        [
          "| `",
          Integer.to_string(code),
          "` | `",
          Atom.to_string(name),
          "` | ",
          Map.fetch!(glosses, name),
          " |\n"
        ]
      end)

    [
      """

      ## Errors

      Every code `Ouroboros.Gateway.Methods.code/1` answers to. `data` is present only
      where a code carries one; two of them are **structured and branched on** rather than
      displayed, and both are pinned by a fixture below.

      | code | name | meaning |
      |---|---|---|
      """,
      rows,
      "\nThe pinned error frames:\n",
      error_fixtures()
    ]
  end

  defp error_fixtures do
    @fixture_owners
    |> Enum.filter(fn {_name, owner} -> match?({:error, _}, owner) end)
    |> Enum.sort_by(fn {name, _owner} -> name end)
    |> Enum.map(fn {name, {:error, code_name}} ->
      ["\n### `", Atom.to_string(code_name), "` — `", name, ".json`\n", fixture_block(name)]
    end)
  end

  # ---------------------------------------------------------------------------

  defp transcript_section do
    corpus = Golden.transcript_corpus()

    entries =
      Enum.map(corpus, fn {name, gloss, plane, _sequence, type, _payload, _fields} ->
        [
          "\n### `",
          name,
          ".json` — `",
          Atom.to_string(type),
          "`\n\n",
          gloss,
          ". Rides `",
          method_for(plane),
          "`.\n",
          fixture_block(name)
        ]
      end)

    [
      """

      ## Transcript payloads

      One frame per event payload a client turns into words. The frames in
      [Notifications](#notifications) pin the envelope — the framing, the resync cursor,
      the excerpt marker — and say almost nothing about what is inside `payload`; these
      say only that. They exist because the protocol has more than one client that has to
      read the same bytes into the same sentences, and a payload that appears in neither
      suite is a payload the two are free to disagree about.

      What a client should *do* with each of them — which cell it becomes, how a tool call
      and its result are correlated, why an unrecognised kind is drawn rather than dropped
      — is presentation rather than protocol, and belongs to the client. What is pinned
      here is narrower and is the whole contract: these bytes, on the wire, from this
      build.

      Every payload's field names are the emitting module's own. Two consequences are
      worth reading before writing a decoder against them:

      * **The ACP dialect does not normalize.** `tool_call`, `tool_result`, `plan_updated`
        and `usage` on that path carry the agent's raw `sessionUpdate` object, camelCase
        included, so a decoder that reads only `call_id` finds nothing and must also read
        `toolCallId`. Only `file_change` is normalized on that path.
      * **A payload leaf may not be the type it was.** Any string above the listener's
        per-leaf cap arrives as `{"_excerpt", "_bytes"}` and any binary as
        `{"_b64", "_bytes"}`, so `payload.diff` is sometimes a map. The two shapes are
        pinned side by side in `interactive_event_excerpt_notification.json` and
        `interactive_event_detail_result.json`.

      #{length(corpus)} frames follow, in reading order rather than alphabetical: what a
      person typed, what the agent said, what it ran, what changed, the bookkeeping, the
      turn, the session, the run, the approvals, the provider's own events, and the two
      types this runtime mints itself.
      """,
      entries
    ]
  end

  defp method_for(:interactive), do: "interactive.event"
  defp method_for(:coding), do: "coding.event"

  # ---------------------------------------------------------------------------

  defp notifications_section do
    grouped =
      @fixture_owners
      |> Enum.filter(fn {_name, owner} -> match?({:notification, _}, owner) end)
      |> Enum.group_by(fn {_name, {:notification, method}} -> method end, fn {name, _} -> name end)
      |> Enum.sort()

    sections =
      Enum.map(grouped, fn {method, fixtures} ->
        [first | _] = Enum.sort(fixtures)
        keys = fixture_json(first)["params"] |> Map.keys() |> Enum.sort()

        [
          "\n### `",
          method,
          "`\n\n",
          "Params: ",
          keys |> Enum.map(&["`", &1, "`"]) |> Enum.intersperse(", "),
          ".\n",
          Enum.map(Enum.sort(fixtures), fn fixture ->
            ["\n`", fixture, ".json`:\n", fixture_block(fixture)]
          end)
        ]
      end)

    [
      """

      ## Notifications

      Frames the server sends with no `id`, which a client must accept at any time after
      `hello`. Their delivery rules — when a stream ends, what a client does about
      `stream.lagged`, why an event leaf may arrive as an excerpt — are narrative and live
      in [docs/TUI.md §2.5 and §2.6](TUI.md).
      """,
      sections
    ]
  end

  # ---------------------------------------------------------------------------

  defp methods_section do
    table = Methods.table()
    params = Methods.params()

    sections =
      Enum.map(bands(), fn band ->
        names = band |> methods_in() |> Enum.sort()

        index =
          Enum.map(names, fn name ->
            entry = Map.fetch!(table, name)

            [
              "| [`",
              name,
              "`](#",
              slug(name),
              ") | `",
              Atom.to_string(entry.scope),
              "` | ",
              duration(entry.timeout),
              " |\n"
            ]
          end)

        [
          "\n### ",
          band,
          "\n\n",
          "| method | scope | ceiling |\n|---|---|---|\n",
          index,
          Enum.map(names, &method_section(&1, Map.fetch!(table, &1), Map.fetch!(params, &1)))
        ]
      end)

    [
      """

      ## Methods

      Each method carries the scope its listener must hold, the ceiling its handler runs
      under, and whether its parameter envelope is **closed** — an unknown key is `-32602`
      naming it — or **open**, where the handler reads what it needs and ignores the rest.
      The difference is exactly what a client discovers by sending a typo, so it is stated
      rather than smoothed over.
      """,
      sections
    ]
  end

  defp method_section(name, entry, spec) do
    [
      "\n#### `",
      name,
      "`\n\n",
      facts(name, entry, spec),
      params_block(spec),
      note_block(spec),
      result_block(name),
      errors_block(name, entry, spec)
    ]
  end

  defp facts(name, entry, spec) do
    answered =
      if name in @connection_answered,
        do: "the connection itself, not a dispatch task",
        else: "a supervised task"

    admission =
      case Map.get(entry, :outcome) do
        :unknown ->
          "- **On a ceiling breach the outcome is unknown.** The answer is `-32005` " <>
            "carrying `data` `{\"outcome\": \"unknown\"}`: the gateway stopped waiting, the " <>
            "runtime did not stop working, and the client reconciles by reading rather " <>
            "than by retrying blind.\n"

        _ ->
          ""
      end

    [
      "- Scope: `",
      Atom.to_string(entry.scope),
      "`\n",
      "- Ceiling: ",
      duration(entry.timeout),
      "\n",
      "- Envelope: ",
      envelope_word(spec.envelope),
      "\n",
      "- Answered by: ",
      answered,
      "\n",
      admission
    ]
  end

  defp envelope_word(:closed), do: "closed — an unknown key is `-32602` naming it"
  defp envelope_word(:open), do: "open — unnamed keys are ignored rather than refused"

  defp params_block(%{params: []}), do: "\nTakes no parameters.\n"

  defp params_block(%{params: params}) do
    rows =
      Enum.flat_map(params, fn param ->
        [
          "| `",
          param.name,
          "` | ",
          requirement(param.requirement),
          " | ",
          type(param.type),
          " | ",
          note(param.note),
          " |\n"
        ] ++ nested_rows(param)
      end)

    ["\n| parameter | | type | notes |\n|---|---|---|---|\n", rows]
  end

  defp nested_rows(%{name: parent, type: type}) do
    type
    |> nested()
    |> Enum.flat_map(fn %{name: name, requirement: requirement, type: inner, note: note} ->
      [
        "| `",
        parent,
        ".",
        name,
        "` | ",
        requirement(requirement),
        " | ",
        type(inner),
        " | ",
        note(note),
        " |\n"
      ]
    end)
  end

  defp nested({:object, fields}), do: Enum.map(fields, &normalize/1)
  defp nested({:either, alternatives}), do: Enum.flat_map(alternatives, &nested/1)
  defp nested(_other), do: []

  defp normalize({name, requirement, type, note}),
    do: %{name: name, requirement: requirement, type: type, note: note}

  defp note_block(%{note: nil}), do: ""
  defp note_block(%{note: note}), do: ["\n", note, ".\n"]

  defp result_block(name) do
    @fixture_owners
    |> Enum.filter(fn {_fixture, owner} -> owner == {:method, name} end)
    |> Enum.sort_by(fn {fixture, _owner} -> fixture end)
    |> Enum.map(fn {fixture, _owner} ->
      ["\nPinned result, `", fixture, ".json`:\n", fixture_block(fixture)]
    end)
  end

  defp errors_block(name, entry, spec) do
    always = ["`-32600` a frame with no id", "`-32700` a line that is not JSON"]

    envelope =
      case spec.envelope do
        :closed -> ["`-32602` an unknown key, a missing one, or a value of the wrong shape"]
        :open -> ["`-32602` a missing parameter or one of the wrong shape"]
      end

    scope =
      case entry.scope do
        :operate -> ["`-32003` on a listener started at `read` scope"]
        :read -> []
      end

    upstream =
      if name in @connection_answered do
        []
      else
        [
          "`-32004` the plane that answers is down or unconfigured",
          "`-32005` the handler outlived " <> duration(entry.timeout),
          "`-32006` the plane refused, with the reason in `data`"
        ]
      end

    handshake =
      if name == "hello",
        do: ["`-32001` the wrong token", "`-32002` a protocol version this build does not speak"],
        else: []

    shutdown =
      if name == "runtime.shutdown",
        do: ["`-32003` again without `OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1` on the daemon"],
        else: []

    codes = handshake ++ scope ++ shutdown ++ envelope ++ always ++ upstream

    [
      "\nCan answer: ",
      codes |> Enum.intersperse(", "),
      ". This is the set every method of this shape can answer, derived from its table " <>
        "entry and its envelope — not an enumeration of the named refusals a plane may " <>
        "put in `data`, which [docs/TUI.md §2.4](TUI.md) lists per method.\n"
    ]
  end

  # ---------------------------------------------------------------------------

  defp limits_section do
    """

    ## What this is not

    **Not a client library.** H3 delivers this reference; the thin TypeScript and Python
    clients that slice also mentions are not written, and nothing here should be read as
    describing one that exists.

    **Not an exhaustive schema.** A golden fixture is a *pinned shape* — one real frame,
    frozen so that the Elixir runtime and the Rust client cannot drift apart without a
    test failing. It is not an enumeration of every value a field can take, and a client
    must treat every result object as open: the planes add keys, and a decoder that
    refuses an unknown one will break on the next release.

    **Not the numbers.** The byte caps on an event leaf and an event payload, the outbound
    queue limit, the maximum frame, the bind address, the scope, and the token source are
    all listener configuration read at boot from `config/runtime.exs` — the
    `OUROBOROS_GATEWAY_*` variables. Pinning them here would state one deployment's
    settings as if they were the protocol.

    **Not the narrative.** Why the design is what it is, and what a client should do about
    each failure it can meet, is [docs/TUI.md §2](TUI.md). Where the two disagree, the code
    wins, this file follows the code, and the disagreement is a bug in TUI.md.

    **Not a list of the refusals a plane can name.** The per-method "can answer" line is
    derived from the method's table entry and its envelope. A plane's own typed refusals —
    `unsupported_on_transport`, `shell_refused`, `delegation_failed`, and the rest — travel
    in the `data` of a `-32006` and are documented where they are decided.
    """
  end

  # ---------------------------------------------------------------------------
  # Rendering
  # ---------------------------------------------------------------------------

  defp requirement(:required), do: "**required**"
  defp requirement(:optional), do: "optional"
  defp requirement({:optional, default}), do: ["optional, default `", inspect(default), "`"]

  defp type(:string), do: "nonempty string"
  defp type(:boolean), do: "boolean"
  defp type(:positive_integer), do: "positive integer"
  defp type(:non_negative_integer), do: "non-negative integer"
  defp type(:object), do: "JSON object"
  defp type(:event_limit), do: "integer, 1..100000"
  defp type(:provider), do: "a provider this node serves (see `runtime.providers`)"
  defp type(:node), do: "a machine name or BEAM node this one is connected to"
  defp type(:turn_target), do: "a turn id (nonempty string) or a non-negative turn number"
  defp type({:const, value}), do: ["exactly `", inspect(value), "`"]

  defp type({:integer, low, high}),
    do: ["integer, ", Integer.to_string(low), "..", Integer.to_string(high)]

  defp type({:enum, values}), do: enum(values)
  defp type({:enum_of, values}), do: enum(values)
  defp type({:enum_mfa, {module, fun, args}}), do: module |> apply(fun, args) |> enum()

  defp type({:list, inner, max}),
    do: ["list of at most ", Integer.to_string(max), " ", type(inner), "s"]

  defp type({:object, _fields}), do: "JSON object, fields below"

  defp type({:either, alternatives}),
    do: alternatives |> Enum.map(&type/1) |> Enum.intersperse(", or ")

  defp type({:limits, {module, fun, args}}) do
    %{default: default, max: max} = apply(module, fun, args)
    ["integer, 1..", Integer.to_string(max), ", default `", Integer.to_string(default), "`"]
  end

  # `option_value/3` spells an enum as the map of accepted string to upstream term; the
  # `only_keys` validators spell theirs as a plain list. Both arrive here, and the doc
  # shows the strings a client may send either way.
  defp enum(values) when is_map(values), do: values |> Map.keys() |> enum()

  defp enum(values) when is_list(values) do
    values
    |> Enum.map(&to_string/1)
    |> Enum.sort()
    |> Enum.map(&["`", &1, "`"])
    |> Enum.intersperse(" \\| ")
  end

  defp note(nil), do: ""
  defp note(note), do: note

  defp duration(ms) when ms >= 120_000, do: "#{div(ms, 60_000)} min"
  defp duration(ms), do: "#{div(ms, 1000)}s"

  # ---------------------------------------------------------------------------
  # Bands and anchors
  # ---------------------------------------------------------------------------

  defp bands do
    present = Methods.table() |> Map.keys() |> Enum.map(&band_of/1) |> Enum.uniq()
    known = Enum.filter(@band_order, &(&1 in present))
    known ++ Enum.sort(present -- known)
  end

  defp methods_in(band), do: Methods.table() |> Map.keys() |> Enum.filter(&(band_of(&1) == band))

  defp band_of("hello"), do: "handshake"
  defp band_of(name), do: name |> String.split(".") |> hd()

  # GitHub's own rule: lowercase, drop everything that is not alphanumeric, a space, or a
  # hyphen, then spaces become hyphens. `runtime.status` becomes `runtimestatus`.
  defp slug(text) do
    text
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9 _-]/u, "")
    |> String.replace(" ", "-")
  end

  # ---------------------------------------------------------------------------
  # Fixtures
  # ---------------------------------------------------------------------------

  defp fixture_block(name) do
    ["\n```json\n", name |> Golden.path() |> File.read!(), "```\n"]
  end

  defp fixture_json(name), do: name |> Golden.path() |> File.read!() |> JSON.decode!()

  defp check_fixtures! do
    declared = Golden.fixtures() |> Enum.map(fn {name, _frame} -> name end) |> MapSet.new()
    placed = fixture_owners() |> Map.keys() |> MapSet.new()

    unplaced = declared |> MapSet.difference(placed) |> Enum.sort()
    stale = placed |> MapSet.difference(declared) |> Enum.sort()

    if unplaced != [] or stale != [] do
      Mix.raise(
        "@fixture_owners in #{inspect(__MODULE__)} does not match the golden fixtures: " <>
          "unplaced #{inspect(unplaced)}, stale #{inspect(stale)}. A fixture the reference " <>
          "silently omits and a fixture nobody wrote look the same to a client author."
      )
    end

    :ok
  end

  defp check_glosses! do
    missing = Methods.codes() |> Map.keys() |> Enum.reject(&Map.has_key?(@code_glosses, &1))

    if missing != [] do
      Mix.raise(
        "Ouroboros.Gateway.Methods.codes/0 names #{inspect(Enum.sort(missing))}, which " <>
          "@code_glosses in #{inspect(__MODULE__)} does not describe. A protocol error a " <>
          "client can receive must not reach it undocumented."
      )
    end

    @code_glosses
  end
end
