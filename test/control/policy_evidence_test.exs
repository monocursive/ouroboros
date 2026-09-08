defmodule Ouroboros.Control.PolicyEvidenceTest.DeadLedger do
  @moduledoc """
  A ledger that cannot record anything, so an answer has nowhere to be written.

  Hoisted to top level deliberately: a `defmodule` nested inside a test module takes that
  module's prefix and shadows every alias with the same last segment.
  """
  def record_settled(_attrs, _ledger), do: {:error, :ledger_is_gone}
  def record_denied(_attrs, _ledger), do: {:error, :ledger_is_gone}
end

defmodule Ouroboros.Control.PolicyEvidenceTest do
  @moduledoc """
  S2's corpus: what a human decided, in the form a policy component would have seen it.

  The claims a corpus is worth nothing without: the row holds the *engine's own* document
  rather than one this module built, its fingerprint is the digest the ledger row beside it
  carries, a rule's answer and a component's answer are not evidence of a human's judgement,
  the file is bounded, and a filesystem that has stopped accepting writes never costs the
  answer that discovered it.
  """

  # Not async: `:policy_evidence_root` and `:permissions_ledger` are application environment.
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Control.Permissions
  alias Ouroboros.Control.Permissions.Request
  alias Ouroboros.Control.Permissions.Seam
  alias Ouroboros.Control.PolicyEvidence
  alias Ouroboros.Control.PolicyEvidenceTest.DeadLedger
  alias Ouroboros.Wasm.PolicyEngine

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ouro-policy-evidence-#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)
    previous = Application.get_env(:ouroboros, :policy_evidence_root)
    Application.put_env(:ouroboros, :policy_evidence_root, dir)

    on_exit(fn ->
      File.rm_rf(dir)

      if is_nil(previous),
        do: Application.delete_env(:ouroboros, :policy_evidence_root),
        else: Application.put_env(:ouroboros, :policy_evidence_root, previous)
    end)

    %{dir: dir, session: "evid-#{System.unique_integer([:positive, :monotonic])}"}
  end

  describe "one row per human answer" do
    test "holds the ten keys, the engine's own document, and the ledger's own digest", context do
      request = bash_request(context, "rm -rf build")

      assert :ok =
               Permissions.record("evid-1-#{context.session}", %{
                 decision: :deny,
                 scope: :once,
                 actor: :human,
                 request: request
               })

      assert [row] = rows()

      assert row["tool"] == "bash"
      assert row["mode"] == "execute"
      assert row["decision"] == "deny"
      assert row["scope"] == "once"
      assert row["session_id"] == context.session
      assert row["node"] == to_string(node())
      assert row["permission_entry_id"] == "evid-1-#{context.session}"
      assert {:ok, _at, _offset} = DateTime.from_iso8601(row["at"])

      # The document is the engine's, byte for byte. A corpus that encoded its own would be a
      # corpus of requests this node never sends — the replay would be measuring a component
      # against documents nothing hands it.
      assert {:ok, document} = PolicyEngine.document(Request.new(request))
      assert row["document"] == document

      # And the fingerprint is the one `Control.Permissions` writes into the `:permission`
      # entry beside it, so a contradiction a replay finds can be traced to the ledger row
      # that recorded it. Duplicate this digest instead of sharing it and this goes red.
      fingerprint = Permissions.fingerprint(Request.new(request))
      assert row["fingerprint"]["sha256"] == fingerprint.sha256
      assert row["fingerprint"]["bytes"] == fingerprint.bytes
    end

    test "names the ledger entry only when the ledger accepted it", context do
      Application.put_env(:ouroboros, :permissions_ledger, DeadLedger)
      on_exit(fn -> Application.delete_env(:ouroboros, :permissions_ledger) end)

      # A name nothing is registered under: `EffectLedger`'s own `safe_call/2` turns the exit
      # into a refusal, which is what a ledger that cannot record looks like from here.
      assert {:error, {:effect_ledger_unavailable, _reason}} =
               Permissions.record("evid-dead-#{context.session}", %{
                 decision: :deny,
                 actor: :human,
                 request: bash_request(context, "ls")
               })

      # The answer is still evidence — a human made it — but there is no `:permission` entry
      # for the row to name, and naming one that does not exist would be the audit lying.
      assert [row] = rows()
      assert row["permission_entry_id"] == nil
      assert row["decision"] == "deny"
    end

    test "the file is 0600 inside a 0700 directory", context do
      # Deleted first, so what is asserted is the mode *this module* creates them at rather
      # than the one the test's own `mkdir_p` happened to leave behind.
      File.rm_rf!(context.dir)

      assert :ok =
               Permissions.record("evid-mode-#{context.session}", %{
                 decision: :approve,
                 actor: :human,
                 request: bash_request(context, "ls")
               })

      assert {:ok, %{mode: file}} = File.stat(PolicyEvidence.path())
      assert {:ok, %{mode: dir}} = File.stat(context.dir)
      assert Bitwise.band(file, 0o777) == 0o600
      assert Bitwise.band(dir, 0o777) == 0o700
    end

    test "the mode is set before the file holds a byte, and the directory is not re-opened",
         context do
      # L10. The file was created at the umask's mode and chmodded *after* the first write, so
      # a command line was on disk world-readable for as long as that took. And the directory
      # was chmodded on every append, which put an operator's deliberate `chmod 000` back to
      # 0700 rather than failing visibly.
      File.rm_rf!(context.dir)
      refute File.exists?(context.dir)

      assert :ok = PolicyEvidence.write("entry", human(:deny), request!("ls"))
      assert {:ok, %{mode: mode}} = File.stat(PolicyEvidence.path())
      assert Bitwise.band(mode, 0o777) == 0o600

      # A directory an operator locked down stays locked down, and the write fails rather than
      # re-opening it.
      File.chmod!(context.dir, 0o000)
      on_exit(fn -> File.chmod(context.dir, 0o700) end)

      assert {:error, _reason} = PolicyEvidence.write("entry", human(:deny), request!("ls -la"))
      assert {:ok, %{mode: locked}} = File.stat(context.dir)
      assert Bitwise.band(locked, 0o777) == 0o000
    end

    test "a request too large for the engine's document is a row with no document", context do
      # `document/1` refuses past its bound rather than truncating (D20), and a row with no
      # document is still the fact that a human answered — counted, and counted separately.
      huge = String.duplicate("x", PolicyEngine.max_request_bytes() + 1)

      assert :ok =
               Permissions.record("evid-huge-#{context.session}", %{
                 decision: :deny,
                 actor: :human,
                 request: bash_request(context, "echo " <> huge)
               })

      assert [row] = rows()
      assert row["document"] == nil
      assert {:ok, counts} = PolicyEvidence.count()
      assert counts.without_document == 1
      assert counts.records == 1
    end

    test "count/0 is total: a corpus nobody can read is an error, not an exception (M8)" do
      # S2b serves this under `:read`. `stream/1` guards the stream's *construction*;
      # enumerating it is where a file that has become unreadable raises, and a `:read` verb
      # that raised would be a gateway 500 where a refusal belongs.
      assert :ok = PolicyEvidence.write("entry", human(:deny), request!("ls"))
      assert {:ok, %{records: 1}} = PolicyEvidence.count()

      File.chmod!(PolicyEvidence.path(), 0o000)
      on_exit(fn -> File.chmod(PolicyEvidence.path(), 0o600) end)

      assert {:error, {:policy_evidence_unreadable, _reason}} = PolicyEvidence.count()
    end
  end

  describe "what is not evidence" do
    test "a rule's answer writes nothing", context do
      assert :ok =
               Permissions.record("evid-rule-#{context.session}", %{
                 decision: :approve,
                 actor: :rule,
                 rule_ref: %{scope: :node, id: "n", pattern: "Bash(ls *)"},
                 request: bash_request(context, "ls")
               })

      # A rule's answer is the rule. Replaying a component against decisions the rules already
      # make would measure the rules. Widen `@evidence_actors` and this goes red.
      assert rows() == []
    end

    test "a policy component's own answer writes nothing", context do
      assert :ok =
               Permissions.record("evid-classifier-#{context.session}", %{
                 decision: :approve,
                 actor: :classifier,
                 request: bash_request(context, "ls")
               })

      # The component grading itself is the one measurement that cannot mean anything.
      assert rows() == []
    end

    test "an answer that does not say who made it writes nothing (P5, L11)", context do
      # The reverse mutation the reviewer left standing: `write/3` read
      # `Map.get(answer, :actor, :human)`, so every caller that forgot to say became a human
      # decision in the corpus. An actor is now required and has no default.
      assert :skipped =
               PolicyEvidence.write("entry", %{decision: :deny, scope: :once}, request!("ls"))

      assert rows() == []

      # And through the seam a session actually uses.
      assert :ok =
               Permissions.record("evid-unstated-#{context.session}", %{
                 decision: :deny,
                 request: bash_request(context, "ls")
               })

      assert rows() == []
    end

    test "a client that answered with nobody at the keyboard writes nothing (H4)", context do
      for actor <- [:automation, :runtime] do
        assert :ok =
                 Permissions.record("evid-#{actor}-#{context.session}", %{
                   decision: :approve,
                   actor: actor,
                   request: bash_request(context, "ls")
                 })
      end

      assert rows() == []
    end

    test "an operator can turn the corpus off entirely (M6)", context do
      Application.put_env(:ouroboros, :policy_evidence_enabled, false)
      on_exit(fn -> Application.delete_env(:ouroboros, :policy_evidence_enabled) end)

      refute PolicyEvidence.enabled?()

      assert :ok =
               Permissions.record("evid-off-#{context.session}", %{
                 decision: :deny,
                 actor: :human,
                 request: bash_request(context, "psql 'password=hunter2'")
               })

      # No row, and no file: a node whose operator does not want human command lines on its
      # disk does not get a file with one line in it either.
      assert rows() == []
      refute File.exists?(PolicyEvidence.path())

      # A malformed value leaves it on: the failure this protects against is a node that
      # silently stopped recording the evidence its promotions are measured against.
      Application.put_env(:ouroboros, :policy_evidence_enabled, "no thanks")
      assert PolicyEvidence.enabled?()
    end

    test "the ACP lane's actor is the one its client declared, too (H4)", context do
      # `Control.Permissions.Seam` is the fourth seam a human answer arrives on, and it
      # hard-coded `actor: :human` for every one of them. Its answer is the same
      # `Jido.Harness.ApprovalResponse` the native loop reads, so the declared actor is in
      # `provider_options` and this reads it from there.
      session = "seam-" <> Integer.to_string(System.unique_integer([:positive]))
      on_exit(fn -> Permissions.forget_session(session) end)

      :ok = Seam.bind(%{cwd: context.dir}, %{session_id: session, provider: :codex}, :stdio)

      :ok =
        Seam.answered(:acp, Seam.decision_id("seam-headless"), acp_stash(), %{
          decision: :approve,
          scope: :once,
          reason: nil,
          provider_options: %{"actor" => "headless"}
        })

      assert rows() == []

      # And a person answering the same question is evidence, so "nothing is evidence any
      # more" cannot pass for a fix here either.
      :ok =
        Seam.answered(:acp, Seam.decision_id("seam-human"), acp_stash(), %{
          decision: :approve,
          scope: :once,
          reason: nil,
          provider_options: %{}
        })

      assert [row] = rows()
      assert row["tool"] == "bash"
      assert row["decision"] == "approve"
      assert row["document"] =~ "ls -la"
    end

    test "an answer with no request writes nothing", context do
      assert :ok =
               Permissions.record("evid-bare-#{context.session}", %{
                 decision: :deny,
                 actor: :human,
                 principal: %{session_id: context.session, provider: :native, node: node()}
               })

      # `answered_request/1` builds a request out of a bare principal so the *ledger* row is
      # attributable. That request has no tool, no command and no paths, and a document built
      # from it is evidence of nothing.
      assert rows() == []
    end

    test "an evaluation the rules decided writes nothing", context do
      # `evaluate/1` records its own `:permission` entries with `actor: :rule`. The corpus is
      # human answers, so a node with rules does not fill it with the rules.
      Application.put_env(:ouroboros, :permissions, [{"Bash(ls *)", :allow}])
      on_exit(fn -> Application.delete_env(:ouroboros, :permissions) end)

      assert {:allow, _ref} = Permissions.evaluate(bash_request(context, "ls -la"))
      assert rows() == []
    end
  end

  describe "a write failure never refuses the answer" do
    test "a root that cannot be created is logged once and the answer stands", context do
      # A regular file where the directory has to be: `mkdir_p` answers `:enotdir` and there is
      # nowhere to write. The corpus is not an authority — the ledger is — so the answer that
      # discovered this is recorded exactly as it would have been.
      blocked = Path.join(context.dir, "blocked")
      File.write!(blocked, "not a directory")
      Application.put_env(:ouroboros, :policy_evidence_root, Path.join(blocked, "policy"))
      PolicyEvidence.forget_warning(:enotdir)

      assert :ok =
               Permissions.record("evid-blocked-#{context.session}", %{
                 decision: :deny,
                 actor: :human,
                 request: bash_request(context, "ls")
               })

      assert {:error, :enotdir} =
               PolicyEvidence.write("id", %{decision: :deny, actor: :human}, Request.new(%{}))
    end

    test "no data directory and no seam is a corpus that is skipped, not an error" do
      Application.delete_env(:ouroboros, :policy_evidence_root)

      assert PolicyEvidence.path() == nil
      assert PolicyEvidence.stream() |> Enum.to_list() == []
      assert {:ok, %{records: 0}} = PolicyEvidence.count()

      assert :ok =
               Permissions.record("evid-nowhere", %{
                 decision: :deny,
                 actor: :human,
                 request: %{tool: "bash", command: "ls", mode: :execute}
               })
    end
  end

  describe "reading it back" do
    test "a torn line is yielded as unreadable rather than skipped", context do
      write!(context, [row_line("bash", "deny"), "{not json", row_line("read", "approve")])

      assert [{:ok, first}, :unreadable, {:ok, third}] = Enum.to_list(PolicyEvidence.stream())
      assert first["tool"] == "bash"
      assert third["tool"] == "read"

      # A replay that silently dropped it would report a corpus size that was not the corpus.
      assert PolicyEvidence.count() ==
               {:ok,
                %{
                  records: 2,
                  by_tool: %{"bash" => 1, "read" => 1},
                  without_document: 0,
                  unreadable: 1
                }}
    end

    test "`since` and `tool` filter decoded rows", context do
      write!(context, [
        row_line("bash", "deny", at: "2020-01-01T00:00:00.000000Z"),
        row_line("bash", "approve", at: "2030-01-01T00:00:00.000000Z"),
        row_line("read", "approve", at: "2030-01-01T00:00:00.000000Z")
      ])

      assert PolicyEvidence.stream(since: "2025-01-01T00:00:00Z") |> Enum.count() == 2
      assert PolicyEvidence.stream(tool: "bash") |> Enum.count() == 2

      assert PolicyEvidence.stream(since: "2025-01-01T00:00:00Z", tool: "bash")
             |> Enum.count() == 1
    end
  end

  describe "the bound" do
    test "past ten thousand records the oldest are dropped by one rewrite", context do
      # Seeded in one write rather than through ten thousand fsyncs: the subject is the
      # rewrite, and `enforce_bounds/1` reaches it from the file's size whichever way the file
      # got that big.
      seeded = for n <- 1..10_100, do: row_line("bash", "deny", marker: n)
      write!(context, seeded)

      assert :ok =
               Permissions.record("evid-bound-#{context.session}", %{
                 decision: :deny,
                 actor: :human,
                 request: bash_request(context, "the newest answer")
               })

      # The rewrite runs off the answer path (L9), so this waits for the record to be bounded
      # rather than for `record/2` to return: a human's answer must not pay for a rewrite of
      # sixty-four mebibytes.
      await(fn -> length(rows()) == 9_000 end)
      kept = rows()

      # Down to the low-water mark rather than to exactly the bound: a rewrite to 10 000 would
      # rewrite the whole file again on the next answer.
      assert length(kept) == 9_000
      assert length(kept) < 10_100

      # Oldest first, and the answer that triggered the rewrite is still there. Drop the
      # `Enum.reverse/1` in `drop_oldest/2` and the newest go instead.
      assert List.last(kept)["document"] =~ "the newest answer"
      assert hd(kept)["marker"] > 1_000
      refute Enum.any?(kept, &(&1["marker"] == 1))
    end

    test "a corpus over the byte bound is dropped by bytes rather than by count", context do
      # Rows large enough that sixty-four mebibytes binds before ten thousand records does, so
      # what is proved is the byte half of the bound and not the record half twice.
      big = String.duplicate("q", 7_000)
      seeded = for n <- 1..10_000, do: row_line("bash", "deny", marker: n, padding: big)
      write!(context, seeded)

      assert File.stat!(PolicyEvidence.path()).size > PolicyEvidence.max_bytes()

      assert :ok =
               Permissions.record("evid-bytes-#{context.session}", %{
                 decision: :deny,
                 actor: :human,
                 request: bash_request(context, "ls")
               })

      await(fn -> File.stat!(PolicyEvidence.path()).size <= PolicyEvidence.max_bytes() end)
      assert File.stat!(PolicyEvidence.path()).size <= PolicyEvidence.max_bytes()

      kept = rows()
      assert length(kept) < 9_000, "the byte bound bound this, not the record bound"

      # And the answer that triggered the rewrite is the one row a rewrite can never drop.
      assert List.last(kept)["document"] =~ "ls"
    end
  end

  ## helpers

  defp bash_request(context, command) do
    %{
      principal: %{session_id: context.session, provider: :native, node: node()},
      tool: "bash",
      command: command,
      paths: [],
      mode: :execute,
      domains: [],
      context: %{}
    }
  end

  # The corpus's bound is enforced by a process of its own (L9), so a test about the bound waits
  # for the file rather than for the call that triggered it.
  defp await(fun, attempts \\ 600)
  defp await(_fun, 0), do: flunk("the corpus was not bounded within 60s")

  defp await(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(100)
      await(fun, attempts - 1)
    end
  end

  defp acp_stash do
    %{
      method: "session/request_permission",
      params: %{"toolCall" => %{"name" => "bash", "rawInput" => %{"command" => "ls -la"}}}
    }
  end

  defp human(decision),
    do: %{decision: decision, scope: :once, actor: :human, rule_ref: nil, reason: nil}

  defp request!(command),
    do:
      Request.new(%{
        principal: %{session_id: "evidence-session", provider: :native, node: node()},
        tool: "bash",
        command: command,
        paths: [],
        mode: :execute,
        domains: [],
        context: %{}
      })

  defp rows do
    PolicyEvidence.stream()
    |> Enum.map(fn
      {:ok, row} -> row
      :unreadable -> nil
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp write!(context, lines) do
    File.mkdir_p!(context.dir)
    File.write!(PolicyEvidence.path(), Enum.map_join(lines, "", &(&1 <> "\n")))
  end

  # A row the size and shape of one this module writes — plus a `marker` a real row does not
  # carry, so a test can say which of ten thousand identical answers survived a rewrite. The
  # size is what matters: the gates in `enforce_bounds/1` are measured against real rows.
  defp row_line(tool, decision, opts \\ []) do
    JSON.encode!(%{
      "at" => Keyword.get(opts, :at, "2026-09-08T00:00:00.000000Z"),
      "node" => to_string(node()),
      "session_id" => "seeded-session-id",
      "tool" => tool,
      "mode" => "execute",
      "fingerprint" => %{"sha256" => String.duplicate("a", 64), "bytes" => 12},
      "decision" => decision,
      "scope" => "once",
      "permission_entry_id" => "seeded-permission-entry-id",
      "marker" => Keyword.get(opts, :marker, 0),
      "document" =>
        JSON.encode!(%{
          "tool" => tool,
          "mode" => "execute",
          "input" => %{"command" => Keyword.get(opts, :padding, "a seeded command line")}
        })
    })
  end
end
