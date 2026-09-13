#!/usr/bin/env elixir

# Private, no-network, real-daemon composition host gate. Run from the repository root:
#   elixir scripts/private-daemon-composition.exs
# It owns only the scratch directory it prints and only the daemon published there.

defmodule PrivateComposition do
  @boot_ms 120_000
  @call_ms 120_000
  @secrets ~w(ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY GOOGLE_API_KEY GROQ_API_KEY OPENROUTER_API_KEY XAI_API_KEY MISTRAL_API_KEY DEEPSEEK_API_KEY TOGETHER_API_KEY CEREBRAS_API_KEY PERPLEXITY_API_KEY ZAI_API_KEY AWS_SECRET_ACCESS_KEY)
  @scoped ~w(OUROBOROS_NATIVE_MODEL OUROBOROS_DATA_DIR XDG_CONFIG_HOME ELIXIR_ERL_OPTIONS OUROBOROS_GATEWAY_SCOPE OUROBOROS_GATEWAY_ALLOW_SHUTDOWN)

  def run do
    repo = File.cwd!()
    ouro = Path.join(repo, "tui/target/release/ouro")

    scratch =
      Path.join(
        repo,
        "tmp/private-daemon-composition-#{Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)}"
      )

    data = Path.join(scratch, "data")
    workspace = Path.join(scratch, "workspace")
    config_home = Path.join(scratch, "config")
    scripts = Path.join(scratch, "model")
    Enum.each([scratch, data, workspace, config_home, scripts], &private_dir!/1)
    receipt = Path.join(scratch, "receipt.json")

    state = %{
      repo: repo,
      ouro: ouro,
      scratch: scratch,
      data: data,
      workspace: workspace,
      config: config_home,
      scripts: scripts,
      receipt: receipt,
      daemon_pid: nil,
      daemon_birth: nil
    }

    IO.puts("scratch=#{scratch}")
    Process.put(:composition_stage, :bootstrap)

    passed =
      try do
        require!(File.regular?(ouro), "build #{ouro} first")
        stage!(:compile_model)
        compile_model!(state)
        stage!(:write_scripts)
        write_scripts!(state)
        stage!(:first_start)
        state = start!(state)
        first_pid = state.daemon_pid
        stage!(:initial_turn)
        {public_id, native_id} = initial_turn!(state)
        stage!(:create_201_events)
        create_201_events!(state, public_id)

        stage!(:handoff)

        handoff =
          call!(state, "interactive.handoff", %{
            "id" => public_id,
            "prompt" => "COMPOSITION-HANDOFF",
            "handoff_id" => "composition-child"
          })

        stage!(:handoff_evidence)
        handoff_event = handoff_event!(state, public_id)

        require!(
          get_in(handoff_event, ["payload", "files"]) == 201 and
            get_in(handoff_event, ["payload", "files_in_packet"]) == 200 and
            get_in(handoff_event, ["payload", "files_omitted"]) == 1,
          "handoff event counts were not 201/200/1: #{inspect(handoff_event)}"
        )

        context_before = call!(state, "interactive.context", %{"id" => public_id})

        replay_before =
          call!(state, "interactive.replay", %{"id" => public_id, "cursor" => 0, "limit" => 1})

        info_before = call!(state, "interactive.info", %{"id" => public_id})

        require!(
          string(info_before, "cursor") > 200 and is_integer(string(info_before, "event_floor")) and
            length(replay_before) == 1,
          "long public wire response lost cursor/event_floor metadata"
        )

        journal_before =
          call!(state, "interactive.journal", %{"id" => public_id, "since_seq" => 0, "limit" => 1})

        require!(
          journal_before["count"] >= 1 and is_integer(journal_before["head_seq"]),
          "long journal metadata missing"
        )

        stage!(:first_stop)
        stop_owned!(state)
        stage!(:restart)
        state = start!(%{state | daemon_pid: nil, daemon_birth: nil})
        require!(state.daemon_pid != first_pid, "daemon did not undergo an actual BEAM restart")
        info = call!(state, "interactive.info", %{"id" => public_id})

        require!(
          string(info, "provider_session_id") == native_id,
          "provider identity changed across restart"
        )

        require!(string(info, "id") == public_id, "public identity changed across restart")
        stage!(:fresh_tool_turn)
        fresh_tool_turn!(state, public_id)
        context_after = call!(state, "interactive.context", %{"id" => public_id})

        require!(
          context_after["provider_session_id"] == context_before["provider_session_id"],
          "context identity changed"
        )

        stage!(:handoff_retry)

        handoff_retry =
          call!(state, "interactive.handoff", %{
            "id" => public_id,
            "prompt" => "COMPOSITION-HANDOFF",
            "handoff_id" => "composition-child"
          })

        require!(handoff_retry["id"] == handoff["id"], "handoff exact retry did not reconcile")

        write_receipt!(state, %{
          status: "passed",
          public_id: public_id,
          native_id: native_id,
          first_pid: first_pid,
          restarted_pid: state.daemon_pid,
          handoff:
            Map.merge(
              handoff,
              Map.take(handoff_event["payload"], ["files", "files_in_packet", "files_omitted"])
            ),
          journal: Map.take(journal_before, ["count", "head", "head_seq"]),
          replay: %{
            cursor: string(info_before, "cursor"),
            event_floor: string(info_before, "event_floor")
          },
          fresh_tool: true,
          credential_env: "removed"
        })

        IO.puts("PASS private actual-daemon composition")
        true
      rescue
        error ->
          write_receipt!(state, %{
            status: "failed",
            error: safe_error(error),
            class: inspect(error.__struct__),
            stage: Process.get(:composition_stage),
            stack: safe_stack(__STACKTRACE__)
          })

          IO.puts(:stderr, "FAIL #{inspect(error.__struct__)}: #{safe_error(error)}")
          false
      after
        cleanup!(state)
      end

    unless passed, do: System.halt(1)
  end

  def cleanup_self_test do
    scratch =
      Path.join(
        File.cwd!(),
        "tmp/private-daemon-composition-cleanup-test-#{Base.url_encode64(:crypto.strong_rand_bytes(8), padding: false)}"
      )

    data = Path.join(scratch, "data")
    private_dir!(scratch)
    private_dir!(data)
    receipt = Path.join(scratch, "receipt.json")
    original = JSON.encode!(%{status: "failed", stage: "synthetic_primary"})
    File.write!(receipt, original)

    # A replacement publication must never be adopted merely because it appears in our
    # scratch directory. Use this BEAM's harmless live PID with a deliberately different
    # birth identity; cleanup must leave it and the primary receipt untouched.
    publication = Path.join(data, "gateway.json")

    File.write!(
      publication,
      JSON.encode!(%{
        "pid" => System.pid() |> String.to_integer(),
        "birth" => "replacement",
        "port" => 1
      })
    )

    Process.put(:composition_daemon, {System.pid() |> String.to_integer(), "original"})
    Process.put(:composition_stage, :synthetic_primary)
    cleanup!(%{data: data, scratch: scratch, receipt: receipt})

    require!(File.read!(receipt) == original, "cleanup replaced the primary receipt")
    require!(File.regular?(publication), "cleanup removed an unexpected publication")
    failure = Path.join(scratch, "cleanup-failure.json") |> File.read!() |> JSON.decode!()
    require!(failure["status"] == "cleanup_failed", "cleanup failure was not recorded")
    IO.puts("PASS cleanup ownership and primary-failure preservation scratch=#{scratch}")
  end

  defp initial_turn!(s) do
    out =
      run_cli!(s, [
        "run",
        "COMPOSITION-INITIAL",
        "--workspace",
        s.workspace,
        "--approval-mode",
        "prompt",
        "--sandbox-mode",
        "workspace_write",
        "--approve-all",
        "--stream-json",
        "--timeout",
        "120"
      ])

    events = ndjson(out)
    result = one!(events, "result")
    public_id = result["session_id"] || result["id"]
    require!(is_binary(public_id), "initial result omitted public identity")
    info = call!(s, "interactive.info", %{"id" => public_id})
    native_id = string(info, "provider_session_id")
    require!(is_binary(native_id), "interactive.info omitted native identity")
    {public_id, native_id}
  end

  defp create_201_events!(s, id) do
    Enum.each(1..201, fn n ->
      prompt = "COMPOSITION-FILE-#{n}"

      out =
        run_cli!(s, [
          "run",
          prompt,
          "--resume",
          id,
          "--approve-all",
          "--stream-json",
          "--timeout",
          "60"
        ])

      require!(
        one!(ndjson(out), "result")["status"] == "completed",
        "file event #{n} did not complete"
      )
    end)

    require!(
      s.workspace |> Path.join("files") |> File.ls!() |> length() == 201,
      "the supported tool turns did not create 201 distinct files"
    )
  end

  defp fresh_tool_turn!(s, id) do
    out =
      run_cli!(s, [
        "run",
        "COMPOSITION-FRESH-PWD",
        "--resume",
        id,
        "--approve-all",
        "--stream-json",
        "--timeout",
        "120"
      ])

    events = ndjson(out)
    calls = Enum.filter(events, &(&1["type"] == "tool_call"))

    require!(
      length(calls) == 1 and get_in(hd(calls), ["payload", "name"]) == "bash",
      "fresh turn was settled or contaminated by historical tool events"
    )

    require!(
      Enum.any?(events, &(&1["type"] == "approval_resolved")),
      "fresh tool call was not freshly approved"
    )

    result = one!(events, "result")
    require!(result["status"] == "completed", "fresh tool turn did not complete")
  end

  defp handoff_event!(s, id), do: find_handoff_page!(s, id, 0)

  # `interactive.replay` is a list, not a cursor envelope. Event `sequence` is the cursor.
  defp find_handoff_page!(s, id, cursor) do
    events = call!(s, "interactive.replay", %{"id" => id, "cursor" => cursor, "limit" => 500})

    case Enum.find(events, fn event ->
           event["type"] == "provider_event" and
             get_in(event, ["payload", "kind"]) == "handoff"
         end) do
      nil when events == [] ->
        raise "public replay ended without required handoff event"

      nil ->
        find_handoff_page!(s, id, List.last(events)["sequence"])

      event ->
        event
    end
  end

  defp write_scripts!(s) do
    fixed = [
      %{"instruction" => "COMPOSITION-INITIAL", "script" => "initial.json"},
      %{"instruction" => "COMPOSITION-HANDOFF", "script" => "handoff.json"},
      %{"instruction" => "COMPOSITION-FRESH-PWD", "script" => "fresh.json"}
    ]

    files =
      1..201
      |> Enum.reverse()
      |> Enum.map(fn n ->
        name = "file-#{n}.json"

        script!(s, name, [
          [tool("write", %{"path" => "files/event-#{n}.txt", "content" => "event #{n}"})],
          [text("file event #{n} complete"), finish()]
        ])

        %{"instruction" => "COMPOSITION-FILE-#{n}", "script" => name}
      end)

    index = files ++ fixed

    File.write!(Path.join(s.scripts, "index.json"), JSON.encode!(%{"entries" => index}))
    script!(s, "initial.json", [[text("initial terminal history"), finish()]])

    script!(s, "handoff.json", [
      [
        text("## Goal\n\nprivate daemon handoff\n\n## Next steps\n\nrun fresh tool turn"),
        finish()
      ]
    ])

    script!(s, "fresh.json", [
      [tool("bash", %{"command" => "pwd", "description" => "fresh identity check"})],
      [text("fresh tool completed"), finish()]
    ])
  end

  defp script!(s, name, responses),
    do:
      File.write!(
        Path.join(s.scripts, name),
        JSON.encode!(%{"instruction" => name, "responses" => responses})
      )

  defp text(v), do: %{"type" => "text", "text" => v}
  defp finish, do: %{"type" => "finish", "reason" => "stop"}

  defp tool(name, input),
    do: %{"type" => "tool_call", "id" => "call", "name" => name, "input" => input}

  defp compile_model!(s) do
    ebin = Path.join(s.repo, "_build/dev/lib/ouroboros/ebin")

    {out, code} =
      System.cmd(
        System.find_executable("elixirc") || "elixirc",
        [
          "--ignore-module-conflict",
          "-o",
          ebin,
          Path.join(s.repo, "scripts/fixture/private_composition_model.ex")
        ],
        cd: s.repo,
        env: [{"ELIXIR_ERL_OPTIONS", "-pa #{ebin}"}],
        stderr_to_stdout: true
      )

    require!(code == 0, "script model compile failed: #{bounded(out)}")
  end

  defp start!(s) do
    assert_credentials_removed!(s)
    log = Path.join(s.scratch, "daemon.stdout")
    {out, code} = run_cli(s, ["--dev", "daemon"], @boot_ms)
    File.write!(log, out, [:append])
    require!(code == 0, "daemon startup failed: #{bounded(out)}")

    require!(
      !String.contains?(out, "already running"),
      "startup adopted an existing fixture daemon"
    )

    publication = await_file!(Path.join(s.data, "gateway.json"), @boot_ms)
    pub = publication |> File.read!() |> JSON.decode!()
    require!(is_integer(pub["pid"]), "publication omitted daemon PID")
    require!(is_binary(pub["birth"]), "publication omitted daemon birth identity")
    Process.put(:composition_daemon, {pub["pid"], pub["birth"]})
    %{s | daemon_pid: pub["pid"], daemon_birth: pub["birth"]}
  end

  defp cleanup!(s) do
    publication = Path.join(s.data, "gateway.json")

    try do
      with {pid, birth} <- Process.get(:composition_daemon),
           true <- File.regular?(publication),
           {:ok, pub} <- publication |> File.read!() |> JSON.decode(),
           true <- pub["pid"] == pid and pub["birth"] == birth,
           owned = %{s | daemon_pid: pid, daemon_birth: birth},
           true <- owned?(owned) do
        {out, code} = run_cli(s, ["stop"], 60_000)

        if code == 0 do
          await_dead!(pid, 60_000)
          await_absent!(publication, 60_000)
        else
          write_cleanup_failure!(s, "authenticated stop failed: #{bounded(out)}")
        end
      else
        nil -> :ok
        false -> write_cleanup_failure!(s, "publication ownership changed; left untouched")
        _ -> write_cleanup_failure!(s, "publication could not be verified; left untouched")
      end
    rescue
      error -> write_cleanup_failure!(s, safe_error(error))
    end

    :ok
  end

  defp write_cleanup_failure!(s, reason) do
    File.write!(
      Path.join(s.scratch, "cleanup-failure.json"),
      JSON.encode!(%{
        status: "cleanup_failed",
        error: reason,
        stage: Process.get(:composition_stage)
      })
    )
  end

  defp stop_owned!(s) do
    publication = Path.join(s.data, "gateway.json")
    require!(File.regular?(publication), "owned daemon publication missing before required stop")
    pub = publication |> File.read!() |> JSON.decode!()

    require!(
      pub["pid"] == s.daemon_pid and pub["birth"] == s.daemon_birth and owned?(s),
      "required stop ownership changed: expected_pid=#{s.daemon_pid} observed_pid=#{pub["pid"]} " <>
        "birth_match=#{pub["birth"] == s.daemon_birth}"
    )

    {out, code} = run_cli(s, ["stop"], 60_000)
    require!(code == 0, "required owned daemon stop failed: #{bounded(out)}")
    await_dead!(s.daemon_pid, 60_000)
    await_absent!(publication, 60_000)
    Process.sleep(2_000)
    require!(!pid_live?(s.daemon_pid), "required owned daemon remained live after stop")
    require!(!File.exists?(publication), "required owned publication reappeared after stop")
  end

  defp owned?(s) do
    with {:ok, body} <- File.read(Path.join(s.data, "gateway.json")),
         {:ok, pub} <- JSON.decode(body),
         true <- pub["pid"] == s.daemon_pid,
         true <- is_nil(s.daemon_birth) or pub["birth"] == s.daemon_birth,
         {_, 0} <-
           System.cmd("kill", ["-0", Integer.to_string(s.daemon_pid)], stderr_to_stdout: true),
         do: true,
         else: (_ -> false)
  end

  defp pid_live?(pid) do
    match?({_, 0}, System.cmd("kill", ["-0", Integer.to_string(pid)], stderr_to_stdout: true))
  end

  defp call!(s, method, params) do
    pub = Path.join(s.data, "gateway.json") |> File.read!() |> JSON.decode!()
    token = pub["token_file"] |> File.read!() |> String.trim()

    {:ok, socket} =
      :gen_tcp.connect(
        ~c"127.0.0.1",
        pub["port"],
        [:binary, packet: :line, active: false, buffer: 8 * 1_048_576],
        5_000
      )

    request = fn id, m, p ->
      :ok =
        :gen_tcp.send(
          socket,
          [
            JSON.encode_to_iodata!(%{
              "jsonrpc" => "2.0",
              "id" => id,
              "method" => m,
              "params" => p
            }),
            ?\n
          ]
        )

      recv!(socket)
    end

    hello =
      request.(1, "hello", %{"token" => token, "protocol" => 1, "client" => "private-composition"})

    require!(hello["result"]["scope"] == "operate", "gateway is not operate scope")
    response = request.(2, method, params)
    :gen_tcp.close(socket)
    require!(!response["error"], "#{method} failed: #{inspect(response["error"])}")
    response["result"]
  end

  defp recv!(socket) do
    case :gen_tcp.recv(socket, 0, @call_ms) do
      {:ok, line} -> JSON.decode!(String.trim(line))
      other -> raise "gateway receive failed: #{inspect(other)}"
    end
  end

  defp run_cli!(s, argv) do
    case run_cli(s, argv, @call_ms) do
      {out, 0} -> out
      {out, code} -> raise "ouro #{hd(argv)} exited #{code}: #{bounded(out)}"
    end
  end

  defp run_cli(s, argv, timeout) do
    task =
      Task.async(fn ->
        System.cmd(s.ouro, argv, cd: s.repo, env: env(s), stderr_to_stdout: true)
      end)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      nil -> {"timed out", 124}
    end
  end

  defp env(s),
    do:
      Enum.map(@secrets ++ @scoped, &{&1, nil}) ++
        [
          {"OUROBOROS_DATA_DIR", s.data},
          {"XDG_CONFIG_HOME", s.config},
          {"OUROBOROS_NATIVE_MODEL", "private-composition:#{s.scripts}"},
          {"ELIXIR_ERL_OPTIONS",
           "-ouroboros native_model_module 'Elixir.Ouroboros.PrivateComposition.Model'"},
          {"OUROBOROS_GATEWAY_SCOPE", "operate"},
          {"OUROBOROS_GATEWAY_ALLOW_SHUTDOWN", "1"}
        ]

  defp assert_credentials_removed!(s) do
    {out, 0} = System.cmd(System.find_executable("env") || "/usr/bin/env", [], env: env(s))

    require!(
      Enum.all?(@secrets, &(not Regex.match?(~r/^#{Regex.escape(&1)}=/m, out))),
      "credential environment survived isolation"
    )
  end

  defp await_file!(path, ms),
    do: await!(fn -> if File.regular?(path), do: path end, ms, "publication")

  defp await_absent!(path, ms),
    do: await!(fn -> if not File.exists?(path), do: :absent end, ms, "publication removal")

  defp await_dead!(pid, ms),
    do:
      await!(
        fn ->
          case System.cmd("kill", ["-0", Integer.to_string(pid)], stderr_to_stdout: true) do
            {_, 0} -> nil
            _ -> :dead
          end
        end,
        ms,
        "daemon stop"
      )

  defp await!(fun, ms, label) do
    deadline = System.monotonic_time(:millisecond) + ms

    Stream.repeatedly(fun)
    |> Enum.find(fn value ->
      if value,
        do: true,
        else:
          (
            require!(
              System.monotonic_time(:millisecond) < deadline,
              "timed out awaiting #{label}"
            )

            Process.sleep(50)
            false
          )
    end)
  end

  defp ndjson(out),
    do:
      out
      |> String.split("\n", trim: true)
      |> Enum.flat_map(fn line ->
        case JSON.decode(line) do
          {:ok, v} when is_map(v) -> [v]
          _ -> []
        end
      end)

  defp one!(events, type),
    do: Enum.find(events, &(&1["type"] == type)) || raise("missing #{type} event")

  defp string(map, key), do: map[key] || map[String.to_atom(key)]

  defp private_dir!(path),
    do:
      (
        File.mkdir_p!(path)
        File.chmod!(path, 0o700)
      )

  defp bounded(v), do: String.slice(v, 0, 8_192)
  defp safe_error(%RuntimeError{message: message}), do: bounded(message)

  defp safe_error(error),
    do: "#{inspect(error.__struct__)} (details redacted; see bounded fixture logs)"

  defp stage!(stage), do: Process.put(:composition_stage, stage)

  defp safe_stack(stack) do
    stack
    |> Enum.take(12)
    |> Enum.map(fn {module, function, args_or_arity, location} ->
      %{
        module: inspect(module),
        function: to_string(function),
        arity: if(is_integer(args_or_arity), do: args_or_arity, else: length(args_or_arity)),
        file: location[:file] && to_string(location[:file]),
        line: location[:line]
      }
    end)
  end

  defp require!(true, _), do: :ok
  defp require!(false, message), do: raise(message)

  defp write_receipt!(s, body),
    do:
      File.write!(
        s.receipt,
        JSON.encode!(Map.put(body, :at, DateTime.utc_now() |> DateTime.to_iso8601()))
      )
end

case System.argv() do
  ["--self-test-cleanup"] -> PrivateComposition.cleanup_self_test()
  [] -> PrivateComposition.run()
  _ -> raise "usage: elixir scripts/private-daemon-composition.exs [--self-test-cleanup]"
end
