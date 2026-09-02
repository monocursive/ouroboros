defmodule Ouroboros.Wasm.ResolutionTest do
  # Not async: the removed-cwd case runs a subprocess, and the plain case reads the global
  # `:ouroboros, :wasm` config. Neither mutates shared state, but they are grouped serial to
  # keep the (heavier) subprocess test off the async schedule.
  use ExUnit.Case, async: false

  alias Ouroboros.Wasm

  test "helper_path/0 is always a string and available?/0 tracks disk" do
    path = Wasm.helper_path()
    assert is_binary(path) and path != ""
    assert Wasm.available?() == File.regular?(path)
  end

  test "OUROBOROS_WASM_HELPER wins over the bundled resolution" do
    override =
      Path.join(System.tmp_dir!(), "ouro-wasm-override-#{System.unique_integer([:positive])}")

    System.put_env("OUROBOROS_WASM_HELPER", override)
    on_exit(fn -> System.delete_env("OUROBOROS_WASM_HELPER") end)

    assert Wasm.helper_path() == override
  end

  describe "config/1 — every setting is a bound, so a typo narrows or falls back" do
    test "a malformed value falls back to the shipped default rather than widening it" do
      defaults = Wasm.all()

      for {key, value} <- [
            handshake_timeout_ms: 0,
            handshake_timeout_ms: -1,
            handshake_timeout_ms: "5000",
            request_timeout_ms: :soon,
            call_margin_ms: 1.5,
            broken_ms: nil,
            max_frame_bytes: 0,
            store_budget_bytes: -1,
            helper_path: "",
            helper_path: 42
          ] do
        put_wasm_config([{key, value}])

        assert Wasm.config(key) == Keyword.fetch!(defaults, key),
               "#{key}: #{inspect(value)} did not fall back"
      end
    end

    test "a value an operator may legitimately move is honoured" do
      put_wasm_config(request_timeout_ms: 45_000, helper_path: "/opt/ouro/ouro-wasm")

      assert Wasm.config(:request_timeout_ms) == 45_000
      assert Wasm.config(:helper_path) == "/opt/ouro/ouro-wasm"
      assert Wasm.helper_path() == "/opt/ouro/ouro-wasm"
    end

    test "a `:wasm` key that is not a keyword list is every default, not a crash" do
      put_wasm_config([])
      Application.put_env(:ouroboros, :wasm, %{request_timeout_ms: 1})

      assert Wasm.config(:request_timeout_ms) == 30_000
      assert Wasm.config(:capability_limits) |> Keyword.fetch!(:fuel) == 100_000_000
    end

    test "the two limits keywords are all three keys or none of them" do
      # A half-stated bound is not a bound: an operator who writes two of the three keys gets
      # the documented default for all three rather than a silently half-configured instance.
      for key <- [:capability_limits, :capability_limits_max] do
        default = Wasm.config(key)

        for bad <- [
              [fuel: 1, memory_bytes: 2],
              [fuel: 1, memory_bytes: 2, deadline_ms: 0],
              [fuel: 1, memory_bytes: 2, deadline_ms: 3, extra: 4],
              [fuel: 1, memory_bytes: 2, deadline_ms: "3"],
              %{fuel: 1, memory_bytes: 2, deadline_ms: 3},
              []
            ] do
          put_wasm_config([{key, bad}])

          assert Wasm.config(key) == default,
                 "#{key}: #{inspect(bad)} was accepted as a partial declaration"
        end

        put_wasm_config([{key, [fuel: 7, memory_bytes: 8, deadline_ms: 9]}])
        assert Wasm.config(key) == [fuel: 7, memory_bytes: 8, deadline_ms: 9]
      end
    end

    test "capability_limits/0 and capability_limits_max/0 are the same decision as maps" do
      put_wasm_config(
        capability_limits: [fuel: 1, memory_bytes: 2, deadline_ms: 3],
        capability_limits_max: [fuel: 4, memory_bytes: 5, deadline_ms: 6]
      )

      assert Wasm.capability_limits() == %{fuel: 1, memory_bytes: 2, deadline_ms: 3}
      assert Wasm.capability_limits_max() == %{fuel: 4, memory_bytes: 5, deadline_ms: 6}
    end

    test "allow_store_root_override? is false unless the node says otherwise" do
      put_wasm_config(allow_store_root_override: false)
      refute Wasm.allow_store_root_override?()

      put_wasm_config(allow_store_root_override: true)
      assert Wasm.allow_store_root_override?()

      # And a non-boolean falls back to the shipped default, which is false.
      put_wasm_config(allow_store_root_override: "yes")
      refute Wasm.allow_store_root_override?()
    end
  end

  @tag :subprocess
  test "helper_path/0 does not raise when the working directory has been removed (F7)" do
    # A bare `Path.expand("priv/wasm/…")` candidate calls `File.cwd!/0`, which raises when the
    # working directory is gone out from under a running node — turning a `Pool.init/1` on the
    # next supervisor restart into a restart storm. Both cwd-derived candidates are gone now
    # (F1) rather than only that one, so nothing here reads the working directory at all.
    # This boots a subprocess normally, removes its cwd from the inside, and then calls
    # `helper_path/0`: it must return a string and exit cleanly.
    doomed = Path.join(System.tmp_dir!(), "ouro-wasm-gone-#{System.unique_integer([:positive])}")

    code = """
    File.mkdir_p!(#{inspect(doomed)})
    File.cd!(#{inspect(doomed)})
    File.rmdir!(#{inspect(doomed)})

    result =
      try do
        if is_binary(Ouroboros.Wasm.helper_path()), do: "STRING", else: "OTHER"
      rescue
        error -> "RAISED:" <> Exception.message(error)
      end

    IO.puts(result)
    """

    {output, status} = run_elixir(code)

    assert status == 0, "helper_path/0 crashed with cwd removed:\n#{output}"
    assert output =~ "STRING", output
  end

  @tag :subprocess
  test "no helper resolver selects a binary planted in a cwd ancestor (F1)" do
    # The finding, for all three resolvers at once. Each of them walked six ancestors of the
    # daemon's working directory looking for `priv/<kind>/<binary>`, and two of them also had
    # a bare `Path.expand("priv/<kind>/…")` candidate. With no bundled helper — the documented
    # default, since nothing in this repo builds one for you — a *cloned repository* that
    # happened to contain that path supplied the binary the daemon spawns as its containment
    # boundary: the wasm helper that contains untrusted guest code, the Computer Use helper
    # that drives the desktop, and the sandbox helper that applies Landlock and seccomp before
    # `execve`ing an untrusted command.
    #
    # The subprocess is what makes this provable rather than incidental. `:code.lib_dir/1`
    # resolves an application from the *first* matching directory on the code path, so an
    # empty `<tmp>/ouroboros/ebin` prepended there makes `:code.priv_dir(:ouroboros)` point at
    # a directory holding none of the three binaries — which is exactly the "no bundled
    # helper" case the finding is about, and the only case in which the walk was ever
    # reached. The modules themselves still load from the real ebin later on the path.
    root = Path.join(System.tmp_dir!(), "ouro-plant-#{System.unique_integer([:positive])}")
    deep = Path.join([root, "some", "worktree"])
    fake_ebin = Path.join([root, "codepath", "ouroboros", "ebin"])
    File.mkdir_p!(deep)
    File.mkdir_p!(fake_ebin)
    on_exit(fn -> File.rm_rf(root) end)

    # Planted twice per helper: once in the working directory itself (which is what the bare
    # `Path.expand("priv/<kind>/…")` candidate read) and once six levels up in an ancestor of
    # it (which is what the walk read). Both shapes are gone, so neither copy may be chosen.
    planted =
      Map.new(
        [
          {:wasm, "wasm", "ouro-wasm"},
          {:desktop, "computer-use", "ouro-computer-use"},
          {:sandbox, "sandbox", "ouro-sandbox"}
        ],
        fn {key, kind, name} ->
          paths =
            for base <- [root, deep] do
              path = Path.join([base, "priv", kind, name])
              File.mkdir_p!(Path.dirname(path))
              File.write!(path, "#!/bin/sh\nexit 0\n")
              File.chmod!(path, 0o755)
              path
            end

          {key, paths}
        end
      )

    code = """
    for name <- ~w(OUROBOROS_WASM_HELPER OUROBOROS_COMPUTER_USE_HELPER OUROBOROS_SANDBOX_HELPER) do
      System.delete_env(name)
    end

    File.cd!(#{inspect(deep)})

    IO.puts("PRIV:" <> inspect(:code.priv_dir(:ouroboros)))
    IO.puts("WASM:" <> Ouroboros.Wasm.helper_path())
    IO.puts("DESKTOP:" <> Ouroboros.Provider.Native.Desktop.helper_path())
    IO.puts("SANDBOX:" <> inspect(Ouroboros.Provider.Native.Sandbox.Helper.executable()))
    """

    {output, status} = run_elixir(code, ["-pa", fake_ebin])
    assert status == 0, output

    lines =
      output
      |> String.split("\n", trim: true)
      |> Enum.flat_map(fn line ->
        case String.split(line, ":", parts: 2) do
          [key, value] -> [{key, value}]
          _other -> []
        end
      end)
      |> Map.new()

    # The fixture is only meaningful if the subprocess really had no bundled helper: its
    # `priv/` is the empty directory beside the fake ebin, which holds none of the three.
    assert lines["PRIV"] =~ Path.join([root, "codepath", "ouroboros", "priv"]), output

    for {key, resolver} <- %{wasm: "WASM", desktop: "DESKTOP", sandbox: "SANDBOX"} do
      resolved = Map.fetch!(lines, resolver)

      for path <- Map.fetch!(planted, key) do
        assert File.regular?(path)

        refute resolved =~ path,
               "#{key}: a helper planted under the working directory was selected " <>
                 "(#{resolved})\n#{output}"
      end
    end
  end

  # Replaces a few keys of the node's `:wasm` config for one test and restores the whole
  # keyword at teardown. This module is `async: false` precisely because this is global, and
  # the restores are LIFO, so the first snapshot taken is the last one put back.
  defp put_wasm_config(overrides) do
    previous = Application.get_env(:ouroboros, :wasm, [])
    on_exit(fn -> Application.put_env(:ouroboros, :wasm, previous) end)
    Application.put_env(:ouroboros, :wasm, Keyword.merge(previous, overrides))
  end

  # One `elixir` with this node's code path, plus whatever `extra` prepends to it.
  defp run_elixir(code, extra \\ []) do
    elixir = System.find_executable("elixir")

    unless elixir do
      flunk("elixir is not on PATH; the resolution regressions need it to run a subprocess")
    end

    args =
      Enum.flat_map(:code.get_path(), &["-pa", List.to_string(&1)]) ++ extra ++ ["-e", code]

    System.cmd(elixir, args, stderr_to_stdout: true)
  end
end
