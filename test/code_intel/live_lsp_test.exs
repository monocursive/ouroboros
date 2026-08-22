defmodule Ouroboros.CodeIntel.LiveLspTest do
  @moduledoc """
  Drives the pool against a real language server, when one happens to be installed.

  Every other test in this directory talks to a fake server, which proves the pool's own
  behaviour and proves nothing about whether this client is protocol-correct against
  software written by somebody else. This one closes that gap where it can: it looks for
  clangd, sourcekit-lsp, or rust-analyzer on `PATH`, and if none is there it skips. It
  never installs anything and it never reaches the network, so it is safe to leave in the
  default run — on a machine with no language servers it is a no-op.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.CodeIntel
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @moduletag :capture_log
  @moduletag :live_lsp

  # Ordered by how little they need to answer a question about a five-line file.
  @candidates [
    {"clangd", :c, "main.c"},
    {"sourcekit-lsp", :swift, "main.swift"},
    {"rust-analyzer", :rust, "src/main.rs"}
  ]

  setup do
    case Enum.find(@candidates, fn {command, _language, _file} ->
           System.find_executable(command)
         end) do
      nil ->
        {:ok, server: nil}

      {command, language, relative} ->
        base =
          Path.join(System.tmp_dir!(), "ouroboros-live-lsp-#{System.unique_integer([:positive])}")

        File.mkdir_p!(base)
        {:ok, root} = WorkspacePath.canonicalize(base)
        source = Path.join(root, relative)
        File.mkdir_p!(Path.dirname(source))
        fixture(language, root, source)

        previous_roots = Application.get_env(:ouroboros, :workspace_allowed_roots, [])
        Application.put_env(:ouroboros, :workspace_allowed_roots, [root])

        on_exit(fn ->
          Application.put_env(:ouroboros, :workspace_allowed_roots, previous_roots)
          File.rm_rf(base)
        end)

        pool_name = :"code_intel_live_#{System.unique_integer([:positive])}"

        start_supervised!(
          {Ouroboros.CodeIntel.Supervisor,
           [
             name: :"code_intel_live_sup_#{System.unique_integer([:positive])}",
             pool_name: pool_name,
             idle_ms: 120_000,
             sweep_ms: 120_000,
             memory_poll_ms: 120_000,
             initialize_timeout_ms: 45_000,
             shutdown_grace_ms: 2_000
           ]}
        )

        {:ok, server: command, language: language, root: root, source: source, pool: pool_name}
    end
  end

  defp fixture(:c, root, source) do
    File.write!(source, """
    int add(int a, int b) { return a + b; }

    int main(void) { return add(1, 2); }
    """)

    File.write!(
      Path.join(root, "compile_commands.json"),
      JSON.encode!([
        %{"directory" => root, "file" => source, "command" => "cc -c #{Path.basename(source)}"}
      ])
    )
  end

  defp fixture(:swift, root, source) do
    File.write!(source, """
    func add(_ a: Int, _ b: Int) -> Int { a + b }
    let total = add(1, 2)
    """)

    File.write!(Path.join(root, "Package.swift"), """
    // swift-tools-version:5.7
    import PackageDescription

    let package = Package(name: "Live", targets: [.executableTarget(name: "Live", path: ".")])
    """)
  end

  defp fixture(:rust, root, source) do
    File.write!(source, """
    fn add(a: i32, b: i32) -> i32 { a + b }

    fn main() { println!("{}", add(1, 2)); }
    """)

    File.write!(Path.join(root, "Cargo.toml"), """
    [package]
    name = "live"
    version = "0.1.0"
    edition = "2021"
    """)
  end

  test "a real language server completes the handshake and answers a question", context do
    if is_nil(context.server) do
      IO.puts(
        "\n[live_lsp] skipped: none of #{inspect(Enum.map(@candidates, &elem(&1, 0)))} on PATH"
      )

      assert true
    else
      IO.puts("\n[live_lsp] using #{context.server} (#{context.language}) at #{context.root}")

      assert {:ok, spec} = CodeIntel.resolve(context.source)
      assert spec.root == context.root

      assert {:ok, handle} = CodeIntel.acquire(context.source, pool: context.pool)
      on_exit(fn -> CodeIntel.release(handle, pool: context.pool) end)

      server =
        await(
          fn ->
            case Enum.find(CodeIntel.status(pool: context.pool).servers, &(&1.root == spec.root)) do
              %{state: :ready} = ready -> {:ok, ready}
              other -> other
            end
          end,
          60_000
        )

      IO.puts(
        "[live_lsp] handshake ok: server_id=#{server.server_id} " <>
          "server_info=#{inspect(server.server_info)} os_pid=#{server.os_pid}"
      )

      assert server.server_id == context.server
      assert is_integer(server.os_pid)

      assert {:ok, symbols} =
               CodeIntel.request(
                 :document_symbols,
                 %{path: context.source, line: 0, character: 0},
                 pool: context.pool,
                 request_timeout_ms: 30_000
               )

      IO.puts(
        "[live_lsp] document_symbols returned #{length(symbols.items)} item(s): " <>
          inspect(Enum.map(symbols.items, &{&1.name, &1.kind}))
      )

      assert Enum.any?(symbols.items, &(&1.name =~ "add")),
             "expected a symbol named add, got #{inspect(symbols.items)}"

      hover =
        CodeIntel.request(:hover, %{path: context.source, line: 0, character: 5},
          pool: context.pool,
          request_timeout_ms: 30_000
        )

      IO.puts("[live_lsp] hover: #{inspect(hover, limit: 3, printable_limit: 200)}")
      assert match?({:ok, %{items: _items}}, hover) or match?({:error, _reason}, hover)

      diagnostics =
        CodeIntel.diagnostics(context.source, pool: context.pool, wait_ms: 10_000)

      IO.puts("[live_lsp] diagnostics: #{inspect(diagnostics, limit: 3, printable_limit: 200)}")

      assert match?({:ok, _snapshot}, diagnostics) or match?({:pending, _version}, diagnostics) or
               match?({:error, _reason}, diagnostics)
    end
  end

  defp await(fun, timeout) do
    do_await(fun, System.monotonic_time(:millisecond) + timeout)
  end

  defp do_await(fun, deadline) do
    case fun.() do
      {:ok, value} ->
        value

      other ->
        if System.monotonic_time(:millisecond) >= deadline do
          flunk("the live server never became ready; last saw #{inspect(other)}")
        else
          Process.sleep(100)
          do_await(fun, deadline)
        end
    end
  end
end
