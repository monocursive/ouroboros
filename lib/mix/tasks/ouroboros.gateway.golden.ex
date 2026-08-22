defmodule Mix.Tasks.Ouroboros.Gateway.Golden do
  @shortdoc "Regenerates the gateway's cross-language golden fixtures"

  @moduledoc """
  Writes `test/support/gateway_golden/*.json` — the frames the `ouro` client decodes.

      mix ouroboros.gateway.golden

  ## Why these files exist

  The protocol has two implementations that are compiled by different toolchains and
  cannot call each other's tests. These files are the seam: this task writes them from the
  same `Ouroboros.Gateway.Conn` envelope functions and the same `Ouroboros.Gateway.Wire`
  encoder the socket is written from, and the Rust client decodes the same bytes in its
  own suite. A change on either side that the other has not accepted shows up as a failing
  test rather than as a field that silently stopped arriving.

  `test/ouroboros/gateway/golden_test.exs` re-derives every frame here through the live
  code and compares, so a fixture cannot drift from the build that produced it. Running
  this task after changing the gateway is how that test goes green again — and the diff it
  produces is the review artifact for a protocol change.

  ## Static by construction

  Nothing here reads the clock, the node name, a random id, or a live plane. Every
  timestamp, id, and sequence is a literal, so regenerating on another machine on another
  day writes the same bytes. The one thing taken from the running build is
  `Ouroboros.Gateway.Methods.names/0` in the `hello` fixture — the method list *is* the
  contract, and a fixture that hid a change to it would defeat the purpose.

  The pid in `runtime_status_result.json` is `:erlang.list_to_pid/1` of a literal, so it
  walks the real `Wire` pid path and still inspects identically everywhere.

  `interactive_event_excerpt_notification.json` states its byte caps rather than taking the
  128 KiB default, for the same reason: a fixture pinning the default would be 128 KiB of
  one repeated character, and the thing a second implementation has to agree about is the
  shape of the marker, not the size of the excerpt. The arithmetic behind the caps is
  asserted in `Ouroboros.Gateway.WireTest`, where numbers belong.

  ## Byte stability

  Objects are written with their keys sorted and two-space indentation by the encoder in
  this module rather than by `JSON.encode!/1`, so a regeneration that changed nothing
  produces a zero-line diff. The bytes are pretty-printed for review; the protocol itself
  is one compact line per frame, and the test asserts both forms decode to the same term.
  """

  use Mix.Task

  alias Ouroboros.CodeIntel.Diagnostics
  alias Ouroboros.Coding.Event, as: CodingEvent
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.Event, as: InteractiveEvent

  @directory "test/support/gateway_golden"

  @node "ouroboros@golden"
  @session_id "session-0000000000000000000001"
  @task_id "task-0000000000000000000000002"
  @timestamp "2026-01-01T00:00:00.000000Z"

  @diagnostic %{
    range: %{start: %{line: 11, character: 4}, end: %{line: 11, character: 12}},
    severity: :error,
    code: "E0425",
    source: "fake",
    message: "cannot find value `widget` in this scope",
    tags: []
  }

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.config")
    File.mkdir_p!(@directory)

    written =
      Enum.map(fixtures(), fn {name, frame} ->
        path = path(name)
        File.write!(path, encode(frame))
        path
      end)

    stale = Path.wildcard(Path.join(@directory, "*.json")) -- written

    Enum.each(stale, fn path ->
      File.rm!(path)
      Mix.shell().info("removed #{path}")
    end)

    Enum.each(written, &Mix.shell().info("wrote #{&1}"))
  end

  @doc "Where one fixture lives, by name."
  @spec path(String.t()) :: Path.t()
  def path(name), do: Path.join(@directory, name <> ".json")

  @doc "The directory holding every fixture."
  @spec directory() :: Path.t()
  def directory, do: @directory

  @doc """
  Every fixture, as `{name, frame}` where `frame` came from the live envelope functions.

  Public because the test that proves these files match the build calls it. Building the
  frames anywhere other than through `Ouroboros.Gateway.Conn` would make the comparison
  circular — it would prove the fixtures match themselves.
  """
  @spec fixtures() :: [{String.t(), map()}]
  def fixtures do
    [
      {"hello_result", hello_result()},
      {"runtime_status_result", runtime_status_result()},
      {"interactive_event_notification", interactive_event_notification()},
      {"coding_event_notification", coding_event_notification()},
      {"interactive_event_excerpt_notification", interactive_event_excerpt_notification()},
      {"interactive_event_detail_result", interactive_event_detail_result()},
      {"coding_event_detail_result", coding_event_detail_result()},
      {"code_intel_diagnostics_result", code_intel_diagnostics_result()},
      {"stream_lagged_notification", stream_lagged_notification()},
      {"stream_ended_notification", stream_ended_notification()},
      {"error_unauthenticated", error_unauthenticated()},
      {"error_protocol_mismatch", error_protocol_mismatch()},
      {"error_scope_denied", error_scope_denied()},
      {"error_upstream_timeout_unknown", error_upstream_timeout_unknown()},
      {"error_cursor_pruned", error_cursor_pruned()},
      {"error_not_found", error_not_found()},
      {"error_invalid_request", error_invalid_request()}
    ]
  end

  @doc """
  Encodes one frame as the bytes a fixture file holds: sorted keys, two-space indent.

  `JSON.encode!/1` is what the socket uses and it does not sort or indent. Both encoders
  produce the same term; only this one produces the same *bytes* on every machine, which
  is what keeps a regeneration from being a diff nobody can review.
  """
  @spec encode(term()) :: iodata()
  def encode(value), do: [pretty(value, ""), ?\n]

  defp hello_result do
    Conn.result_frame(1, %{
      "server" => "0.1.0",
      "node" => @node,
      "role" => "core",
      "protocol" => 1,
      "scope" => "operate",
      "methods" => Methods.names()
    })
  end

  # A hand-written term in the shape `Ouroboros.status/0` returns, not a capture of a live
  # node: the point is to pin the *encoding* of every leaf kind a client has to render —
  # tri-state availability words, an opaque pid inside an otherwise readable map, atoms as
  # strings, empty lists — while staying identical on every machine. A client must treat
  # each nested status map as open: the planes add keys and this is a projection.
  defp runtime_status_result do
    Conn.result_frame(2, %{
      node: :ouroboros@golden,
      role: :core,
      connected_nodes: [],
      # The exact shape `Ouroboros.Cluster.status/0` returns — no `mode` key, whatever the
      # `%{mode: :unavailable}` fallback in `Ouroboros.status/0` might suggest to a client
      # author reading only that line.
      cluster: %{
        node: :ouroboros@golden,
        role: :core,
        distributed: false,
        connected_nodes: [],
        roles: %{core: [], builder: [], signer: [], unreachable: []},
        formation: %{strategy: :none, topologies: [], supervised: false},
        security: %{
          distributed: false,
          proto_dist: :inet_tcp,
          tls: false,
          cookie: :unset
        }
      },
      availability: %{
        cluster: :available,
        mesh: :available,
        coding: :available,
        interactive: :available,
        teams: :available,
        orchestration: :available,
        control: :disabled,
        effect_ledger: :available,
        workspace: :disabled,
        hot_upgrade: :available,
        release: :available
      },
      agents: [
        %{
          id: "reviewer-1",
          pid: :erlang.list_to_pid(~c"<0.123.0>"),
          node: :ouroboros@golden,
          replicas: 1
        }
      ],
      coding_tasks: [
        %{
          id: @task_id,
          node: :ouroboros@golden,
          provider: :codex,
          status: :running,
          created_at: @timestamp,
          updated_at: @timestamp
        }
      ],
      interactive_sessions: [
        %{
          id: @session_id,
          node: :ouroboros@golden,
          provider: :claude_code,
          status: :idle,
          created_at: @timestamp,
          updated_at: @timestamp
        }
      ],
      teams: [
        %{
          id: "team-alpha",
          status: :active,
          worker_count: 2,
          delegation_count: 1,
          updated_at: @timestamp
        }
      ],
      orchestration_plans: [],
      control: %{runs: []},
      effect_ledger: %{
        durability: :synced_checkpoint,
        retained: 3,
        in_flight: 1,
        ambiguous: 0,
        retention_limit: 1_000,
        next_sequence: 5
      },
      upgrade: %{
        node: :ouroboros@golden,
        mode: :ready,
        quarantine_reason: nil,
        last_epoch: 7,
        prepared: [],
        rollback_receipts: [],
        operations: []
      },
      release: %{mode: :ready, handler_releases: [], ephemeral_capability_count: 0},
      forge: %{signer: :deny, admit_possible?: false, live_count: 0, live: []}
    })
  end

  # A realistic event: the payload is already redacted where it is constructed
  # ([interactive/event.ex](../lib/ouroboros/interactive/event.ex)) and the gateway adds no
  # raw surface, so what a client renders is what this shows. `sequence` is the resync
  # cursor the whole streaming contract turns on.
  defp interactive_event_notification do
    Conn.notification_frame("interactive.event", %{
      "id" => @session_id,
      "event" => %InteractiveEvent{
        id: "evt-0000000000000000000000001",
        session_id: @session_id,
        sequence: 42,
        type: :output_text_final,
        timestamp: @timestamp,
        payload: %{"text" => "the workspace is clean", "token" => "[REDACTED]"},
        harness_session_id: "harness-0000000000000000001",
        provider: :claude_code,
        provider_session_id: "provider-0000000000000001",
        turn_id: "turn-0000000000000000000001",
        request_id: nil
      }
    })
  end

  # The coding struct names its session `task_id`, not `session_id`, while the
  # notification's own `id` parameter is the same value under the name every other method
  # uses. Both spellings are in this fixture on purpose.
  defp coding_event_notification do
    Conn.notification_frame("coding.event", %{
      "id" => @task_id,
      "event" => %CodingEvent{
        id: "evt-0000000000000000000000002",
        task_id: @task_id,
        sequence: 17,
        type: :run_completed,
        timestamp: @timestamp,
        payload: %{"text" => "objective satisfied"},
        provider: :codex,
        provider_session_id: "provider-0000000000000002",
        harness_sequence: 31
      }
    })
  end

  # One `file_change` payload, four rules at once. The caps are stated at 48 and 96 bytes
  # rather than left at the 128 KiB and 512 KiB defaults, so this file pins the *shape* —
  # `_excerpt` beside `_bytes` — in bytes a reviewer can read:
  #
  #   * `diff` spends the per-leaf cap and names its true size.
  #   * `note` is cut where a three-byte character straddles the boundary, so it retreats
  #     to the last whole character and the excerpt is 46 bytes rather than 48. A client
  #     decoding this frame is owed valid UTF-8.
  #   * `path` is short enough that the marker map would cost more than the string, so it
  #     is left whole even though the budget is already gone.
  #   * `tail` arrives after the budget is spent: the excerpt is empty and `_bytes` is the
  #     only thing left that is true about it.
  #
  # Every envelope field is untouched, because a client resyncs by `sequence`.
  defp interactive_event_excerpt_notification do
    Conn.notification_frame(
      "interactive.event",
      %{"id" => @session_id, "event" => excerpted_event()},
      event_leaf_bytes: 48,
      event_payload_bytes: 96
    )
  end

  # The answer to `interactive.event_detail`: one event, bare — not an array and not
  # wrapped, because `interactive.replay` is the method that answers with a list. It is the
  # same event as the notification above, encoded under the raised `detail_leaf_bytes` cap
  # that is the whole reason the method exists, so a reviewer can read the two files side
  # by side and see the excerpts become the leaves they came from.
  defp interactive_event_detail_result do
    Conn.result_frame(7, excerpted_event(),
      event_leaf_bytes: 8_388_608,
      event_payload_bytes: 8_388_608
    )
  end

  defp coding_event_detail_result do
    Conn.result_frame(
      8,
      %CodingEvent{
        id: "evt-0000000000000000000000004",
        task_id: @task_id,
        sequence: 18,
        type: :file_change,
        timestamp: @timestamp,
        payload: %{"diff" => String.duplicate("b", 600)},
        provider: :codex,
        provider_session_id: "provider-0000000000000002",
        harness_sequence: 32
      },
      event_leaf_bytes: 8_388_608,
      event_payload_bytes: 8_388_608
    )
  end

  defp excerpted_event do
    %InteractiveEvent{
      id: "evt-0000000000000000000000003",
      session_id: @session_id,
      sequence: 43,
      type: :file_change,
      timestamp: @timestamp,
      payload: %{
        "diff" => String.duplicate("a", 600),
        "note" => "x" <> String.duplicate("☃", 200),
        "path" => "lib/ouroboros/gateway/wire.ex",
        "tail" => String.duplicate("z", 700)
      },
      harness_session_id: "harness-0000000000000000001",
      provider: :claude_code,
      provider_session_id: "provider-0000000000000001",
      turn_id: "turn-0000000000000000000001",
      request_id: nil
    }
  end

  defp stream_lagged_notification do
    Conn.notification_frame("stream.lagged", %{
      "id" => @session_id,
      "plane" => "interactive",
      "dropped" => 128,
      "last_sequence" => 512
    })
  end

  defp stream_ended_notification do
    Conn.notification_frame("stream.ended", %{
      "id" => @session_id,
      "plane" => "interactive",
      "status" => "closed"
    })
  end

  defp error_unauthenticated do
    Conn.error_frame(
      1,
      Methods.code(:unauthenticated),
      "hello did not present the token this listener was started with"
    )
  end

  defp error_protocol_mismatch do
    Conn.error_frame(
      1,
      Methods.code(:protocol_mismatch),
      "this gateway speaks protocol 1, the client asked for 2",
      %{"server_protocol" => 1}
    )
  end

  defp error_scope_denied do
    Conn.error_frame(
      3,
      Methods.code(:scope_denied),
      "interactive.start mutates the runtime and this listener was started with " <>
        "OUROBOROS_GATEWAY_SCOPE=read"
    )
  end

  # The `:infinity` verbs. A gateway ceiling stops the waiting, not the work, so the
  # answer says which of the two it is: the client reconciles by reading `teams.state`.
  defp error_upstream_timeout_unknown do
    Conn.error_frame(
      4,
      Methods.code(:upstream_timeout),
      "teams.close exceeded the gateway ceiling of 60000ms; the runtime may still be " <>
        "working on it",
      %{"outcome" => "unknown"}
    )
  end

  # The one error whose `data` a client branches on rather than displays: it restarts from
  # `floor` and marks everything below it as truncated history.
  defp error_cursor_pruned do
    Conn.error_frame(
      5,
      Methods.code(:upstream_error),
      "the session no longer retains events at or below that cursor; replay from 96",
      %{"reason" => "cursor_pruned", "floor" => 96}
    )
  end

  # E2. One diagnostics answer, with the field that makes the new-only rule work across a
  # process boundary: `signature` is derived here through the live
  # `CodeIntel.Diagnostics.signature/1`, so a change to what "the same diagnostic" means
  # is a diff in this file rather than a hook that silently starts re-reporting fixed
  # errors. Positions stay 0-based, exactly as the protocol reports them.
  defp code_intel_diagnostics_result do
    Conn.result_frame(9, %{
      status: :ok,
      version: 4,
      source: "fake",
      truncated: 0,
      counts: %{error: 1, warning: 0, information: 0, hint: 0, unknown: 0},
      items: Enum.map([@diagnostic], &Map.put(&1, :signature, Diagnostics.signature(&1)))
    })
  end

  defp error_not_found do
    Conn.error_frame(6, Methods.code(:not_found), "no such record on this node")
  end

  defp error_invalid_request do
    Conn.error_frame(
      nil,
      Methods.code(:invalid_request),
      "every request must carry a string or number id; this protocol has no client " <>
        "notifications"
    )
  end

  defp pretty(value, _indent) when is_map(value) and map_size(value) == 0, do: "{}"
  defp pretty([], _indent), do: "[]"

  defp pretty(value, indent) when is_map(value) do
    inner = indent <> "  "

    pairs =
      value
      |> Enum.sort_by(fn {key, _value} -> key end)
      |> Enum.map(fn {key, member} ->
        [inner, JSON.encode!(key), ": ", pretty(member, inner)]
      end)

    ["{\n", Enum.intersperse(pairs, ",\n"), "\n", indent, "}"]
  end

  defp pretty(value, indent) when is_list(value) do
    inner = indent <> "  "
    members = Enum.map(value, fn member -> [inner, pretty(member, inner)] end)

    ["[\n", Enum.intersperse(members, ",\n"), "\n", indent, "]"]
  end

  defp pretty(value, _indent), do: JSON.encode!(value)
end
