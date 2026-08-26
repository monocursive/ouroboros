defmodule Ouroboros.Control.PermissionsPatternTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Control.Permissions.{Matcher, Pattern, Request, Rule, Shell}

  # ── The rule language ──────────────────────────────────────────────────────────────

  describe "the pattern language" do
    test "parses every form the language contains" do
      assert %Pattern{kind: :bash, spec: %{match: :word_prefix, prefix: "ls"}} =
               Pattern.parse!("Bash(ls *)")

      assert %Pattern{kind: :bash, spec: %{match: :literal_prefix, prefix: "npm run test:"}} =
               Pattern.parse!("Bash(npm run test:*)")

      assert %Pattern{kind: :bash, spec: %{match: :exact, prefix: "npm run build"}} =
               Pattern.parse!("Bash(npm run build)")

      assert %Pattern{kind: :read, spec: %{glob: "./.env"}} = Pattern.parse!("Read(./.env)")
      assert %Pattern{kind: :edit, spec: %{glob: "/src/**"}} = Pattern.parse!("Edit(/src/**)")

      assert %Pattern{kind: :write, spec: %{glob: "docs/*.md"}} =
               Pattern.parse!("Write(docs/*.md)")

      assert %Pattern{kind: :web_fetch, spec: %{domain: "example.com"}} =
               Pattern.parse!("WebFetch(domain:example.com)")

      assert %Pattern{kind: :mcp, spec: %{server: "srv", tool: "query"}} =
               Pattern.parse!("mcp__srv__query")

      assert %Pattern{kind: :mcp, spec: %{server: "srv", tool: :any}} =
               Pattern.parse!("mcp__srv__*")

      assert %Pattern{kind: :tool, spec: %{name: "WebSearch"}} = Pattern.parse!("Tool(WebSearch)")

      assert %Pattern{kind: :tool_param, spec: %{name: "bash", param: "shell", value: "zsh"}} =
               Pattern.parse!("Tool(bash:shell=zsh)")
    end

    test "refuses Bash(command:...) outright, as documented" do
      assert {:error, :bash_command_specifier_refused} = Pattern.parse("Bash(command:rm *)")
    end

    test "a parameter-constrained tool pattern may deny or ask, never allow" do
      pattern = Pattern.parse!("Tool(bash:shell=zsh)")
      assert Pattern.decisions(pattern) == :deny_or_ask_only

      assert {:error, {:pattern_cannot_allow, _raw}} =
               Rule.new(%{scope: :user, decision: :allow, pattern: "Tool(bash:shell=zsh)"})

      assert {:ok, %Rule{decision: :deny}} =
               Rule.new(%{scope: :user, decision: :deny, pattern: "Tool(bash:shell=zsh)"})
    end

    test "argument-constraining Bash patterns are accepted and marked fragile" do
      assert Pattern.fragile?(Pattern.parse!("Bash(curl http://github.com/ *)"))
      assert Pattern.fragile?(Pattern.parse!("Bash(rm -rf *)"))
      assert Pattern.fragile?(Pattern.parse!("Bash(git * --force)"))

      refute Pattern.fragile?(Pattern.parse!("Bash(ls *)"))
      refute Pattern.fragile?(Pattern.parse!("Bash(npm run test:*)"))
    end

    test "refuses what the language does not contain" do
      assert {:error, :empty_pattern} = Pattern.parse("")
      assert {:error, {:unrecognized_pattern, _}} = Pattern.parse("just some words")
      assert {:error, {:unknown_pattern_kind, "Frobnicate", _}} = Pattern.parse("Frobnicate(x)")
      assert {:error, {:web_fetch_requires_domain, _}} = Pattern.parse("WebFetch(github.com)")
      assert {:error, {:invalid_mcp_pattern, _}} = Pattern.parse("mcp__")
      assert {:error, {:pattern_too_long, _}} = Pattern.parse(String.duplicate("x", 600))
      assert {:error, {:invalid_pattern, :not_a_string}} = Pattern.parse(:not_a_string)
    end
  end

  # ── Claude Code's documented Bash cases, as a corpus ───────────────────────────────

  describe "Bash matching, against R3 §3.2's documented cases" do
    test "the word boundary: `Bash(ls *)` covers `ls -la` and never `lsof`" do
      assert bash?("Bash(ls *)", "ls")
      assert bash?("Bash(ls *)", "ls -la")
      assert bash?("Bash(ls *)", "ls -la /tmp /var")
      refute bash?("Bash(ls *)", "lsof")
      refute bash?("Bash(ls *)", "lsof -i")
      refute bash?("Bash(ls *)", "sls")
    end

    test "one star spans every remaining argument" do
      assert bash?("Bash(git commit *)", "git commit -am 'wip and more' --no-verify")
      refute bash?("Bash(git commit *)", "git push")
    end

    test "the colon form is a literal prefix, with no boundary of its own" do
      assert bash?("Bash(npm run test:*)", "npm run test:unit")
      assert bash?("Bash(npm run test:*)", "npm run test:integration -- --watch")
      refute bash?("Bash(npm run test:*)", "npm run build")
    end

    test "a starless pattern is exact" do
      assert bash?("Bash(npm run build)", "npm run build")
      refute bash?("Bash(npm run build)", "npm run build --prod")
    end

    test "compound commands split, and an allow needs every part" do
      assert Shell.split("a && b || c ; d | e |& f & g\nh") == ~w(a b c d e f g h)

      # Every part matches: allowed.
      assert bash?("Bash(git *)", "git status && git diff")
      # One part does not: not allowed, under the :all quantifier an allow rule uses.
      refute bash?("Bash(git *)", "git status && rm -rf /")
      # ...but a deny rule matches on that one part, under :any.
      assert bash?("Bash(rm *)", "git status && rm -rf /", :any)
    end

    test "quoting is respected when splitting" do
      assert Shell.split(~s(echo "a && b")) == [~s(echo "a && b")]
      assert bash?("Bash(echo *)", ~s(echo "a && b"))
    end

    test "wrappers and their options are stripped" do
      for wrapped <- [
            "timeout 5s ls -la",
            "timeout 30 ls -la",
            "time ls -la",
            "nice -n 10 ls -la",
            "nohup ls -la",
            "stdbuf -o0 ls -la",
            "command ls -la",
            "builtin ls -la",
            "noglob ls -la",
            "nohup timeout 5 ls -la",
            "/usr/bin/timeout 5 ls -la"
          ] do
        assert bash?("Bash(ls *)", wrapped), "expected #{inspect(wrapped)} to match Bash(ls *)"
      end
    end

    test "bare xargs is a wrapper; xargs with options is the command" do
      assert bash?("Bash(rm *)", "xargs rm")
      refute bash?("Bash(rm *)", "xargs -I{} rm {}")
      assert bash?("Bash(xargs *)", "xargs -I{} rm {}")
    end

    test "redirect targets are collected as writes" do
      assert Shell.redirect_targets("echo hi > /tmp/out") == ["/tmp/out"]
      assert Shell.redirect_targets("echo hi >> /tmp/out") == ["/tmp/out"]
      assert Shell.redirect_targets("echo hi 2> /tmp/err") == ["/tmp/err"]
      assert Shell.redirect_targets("echo hi>/tmp/out") == ["/tmp/out"]
      assert Shell.redirect_targets("ls; echo hi > a") == ["a"]
      # A descriptor is not a file.
      assert Shell.redirect_targets("ls 2>&1") == []
    end

    test "a redirect on any descriptor is a write, not just 0, 1, and 2" do
      assert Shell.redirect_targets("echo hi 3>/tmp/out") == ["/tmp/out"]
      assert Shell.redirect_targets("echo hi 4>> /tmp/out") == ["/tmp/out"]
      assert Shell.redirect_targets("echo hi 10>/tmp/out") == ["/tmp/out"]
      # The shape that motivated this: the write is on fd 3, and fd 1 is then pointed at
      # it, so nothing about the line looks like a redirect to a file.
      assert Shell.redirect_targets("echo pwned 3>.git/config 1>&3") == [".git/config"]
    end

    test "a clobbering >| is a redirect, not a pipe" do
      assert Shell.split("echo pwned >| f") == ["echo pwned >| f"]
      assert Shell.split("echo pwned >| f | cat") == ["echo pwned >| f", "cat"]
      assert Shell.redirect_targets("echo pwned >| .git/config") == [".git/config"]
      assert Shell.redirect_targets("echo pwned 3>| .git/config") == [".git/config"]
    end

    test "a Bash pattern never matches a request with no command" do
      refute Matcher.matches?(Pattern.parse!("Bash(ls *)"), Request.new(%{tool: "read"}), :any)
    end
  end

  # ── Paths, domains, MCP, tools ─────────────────────────────────────────────────────

  describe "path, domain, MCP, and tool matching" do
    setup do
      root = tmp_root("matcher")
      File.mkdir_p!(Path.join(root, "src"))
      on_exit(fn -> File.rm_rf(root) end)
      {:ok, root: root}
    end

    test "path globs resolve against the workspace root", %{root: root} do
      request =
        Request.new(%{
          tool: "edit",
          mode: :write,
          paths: ["src/app.ex"],
          context: %{workspace: root}
        })

      assert Matcher.matches?(Pattern.parse!("Edit(src/**)"), request, :all)
      assert Matcher.matches?(Pattern.parse!("Edit(**/*.ex)"), request, :all)
      refute Matcher.matches?(Pattern.parse!("Edit(test/**)"), request, :all)
      refute Matcher.matches?(Pattern.parse!("Read(src/**)"), request, :all)
    end

    test "an allow needs every path; a deny needs one", %{root: root} do
      request =
        Request.new(%{
          tool: "write",
          mode: :write,
          paths: ["src/app.ex", "/etc/hosts"],
          context: %{workspace: root}
        })

      refute Matcher.matches?(Pattern.parse!("Write(src/**)"), request, :all)
      assert Matcher.matches?(Pattern.parse!("Write(src/**)"), request, :any)
    end

    test "Edit and Write overlap only where the tool is unrecognised", %{root: root} do
      edit = Request.new(%{tool: "edit", mode: :write, paths: ["a"], context: %{workspace: root}})

      write =
        Request.new(%{tool: "write", mode: :write, paths: ["a"], context: %{workspace: root}})

      other =
        Request.new(%{tool: "mystery", mode: :write, paths: ["a"], context: %{workspace: root}})

      assert Matcher.matches?(Pattern.parse!("Edit(**)"), edit, :all)
      refute Matcher.matches?(Pattern.parse!("Write(**)"), edit, :all)
      assert Matcher.matches?(Pattern.parse!("Write(**)"), write, :all)
      refute Matcher.matches?(Pattern.parse!("Edit(**)"), write, :all)
      assert Matcher.matches?(Pattern.parse!("Edit(**)"), other, :all)
      assert Matcher.matches?(Pattern.parse!("Write(**)"), other, :all)
    end

    test "a domain covers itself and its subdomains, never a suffix collision" do
      fetch = fn host ->
        Request.new(%{tool: "web_fetch", mode: :network, domains: [host]})
      end

      assert Matcher.matches?(
               Pattern.parse!("WebFetch(domain:example.com)"),
               fetch.("example.com"),
               :all
             )

      assert Matcher.matches?(
               Pattern.parse!("WebFetch(domain:example.com)"),
               fetch.("api.example.com"),
               :all
             )

      refute Matcher.matches?(
               Pattern.parse!("WebFetch(domain:example.com)"),
               fetch.("notexample.com"),
               :all
             )

      refute Matcher.matches?(
               Pattern.parse!("WebFetch(domain:*.example.com)"),
               fetch.("example.com"),
               :all
             )
    end

    test "MCP patterns match both spellings of an MCP tool name" do
      colon = Request.new(%{tool: "mcp:srv:query", mode: :execute})
      underscore = Request.new(%{tool: "mcp__srv__query", mode: :execute})

      for request <- [colon, underscore] do
        assert Matcher.matches?(Pattern.parse!("mcp__srv__query"), request, :all)
        assert Matcher.matches?(Pattern.parse!("mcp__srv__*"), request, :all)
        refute Matcher.matches?(Pattern.parse!("mcp__other__*"), request, :all)
      end
    end

    test "Tool matches by name, and Tool(name:param=value) by a context value" do
      request = Request.new(%{tool: "WebSearch", mode: :network, context: %{"shell" => "zsh"}})

      assert Matcher.matches?(Pattern.parse!("Tool(websearch)"), request, :all)
      refute Matcher.matches?(Pattern.parse!("Tool(WebFetch)"), request, :all)
      assert Matcher.matches?(Pattern.parse!("Tool(WebSearch:shell=zsh)"), request, :any)
      refute Matcher.matches?(Pattern.parse!("Tool(WebSearch:shell=bash)"), request, :any)
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────────────

  defp bash?(pattern, command, quantifier \\ :all) do
    Matcher.matches?(
      Pattern.parse!(pattern),
      Request.new(%{tool: "bash", command: command, mode: :execute}),
      quantifier
    )
  end

  defp tmp_root(name) do
    path =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-permissions-#{name}-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(path)
    {:ok, canonical} = Ouroboros.Workspace.Path.canonicalize(path)
    canonical
  end
end
