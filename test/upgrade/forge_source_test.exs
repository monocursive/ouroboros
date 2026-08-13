defmodule Ouroboros.Upgrade.ForgeSourceTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Upgrade.Forge.Source

  @evil Ouroboros.Capability.Evil

  test "accepts a well-formed capability and rejects names outside the namespace" do
    assert {:ok, _source} = validate(Ouroboros.Capability.Greeter, "def hello, do: :world")

    assert {:ok, _nested} =
             validate(Ouroboros.Capability.Text.Summarize, "def summarize(text), do: text")

    for name <- [Ouroboros.Agent.Worker, Ouroboros.Upgrade.Forge, Elixir.Capability, String] do
      assert {:error, {:invalid_module_name, _printed}} = validate(name, "def hello, do: :world")
    end

    # The protected set is enforced by the verifier on the loading node, but a forge that
    # let this through would have compiled it first.
    assert {:error, {:invalid_module_name, "Ouroboros.Upgrade.NodeExecutor"}} =
             validate(Ouroboros.Upgrade.NodeExecutor, "def hello, do: :world")
  end

  test "requires exactly one top-level module and requires it to be the declared one" do
    two = """
    defmodule Ouroboros.Capability.First do
      def hello, do: :world
    end

    defmodule Ouroboros.Capability.Second do
      def hello, do: :world
    end
    """

    assert {:error, {:expected_single_module, modules}} =
             Source.validate(source!(Ouroboros.Capability.First, two))

    assert modules == [Ouroboros.Capability.First, Ouroboros.Capability.Second]

    mismatched = """
    defmodule Ouroboros.Capability.Other do
      def hello, do: :world
    end
    """

    assert {:error, {:module_mismatch, Ouroboros.Capability.Declared, Ouroboros.Capability.Other}} =
             Source.validate(source!(Ouroboros.Capability.Declared, mismatched))

    stray = """
    IO.puts("hello")

    defmodule Ouroboros.Capability.Stray do
      def hello, do: :world
    end
    """

    assert {:error, {:unexpected_top_level_form, 1}} =
             Source.validate(source!(Ouroboros.Capability.Stray, stray))

    assert {:error, {:parse_failed, :source, _reason}} =
             Source.validate(source!(Ouroboros.Capability.Broken, "defmodule do end end ["))
  end

  test "rejects every denied construct by name and line" do
    cases = [
      {"@on_load :boot\n  def boot, do: :ok", :on_load},
      {"def go, do: Code.eval_string(\"1\")", Code},
      {"def go, do: :code.delete(Foo)", :code},
      {"def go, do: System.cmd(\"ls\", [])", {System, :cmd}},
      {"def go, do: System.shell(\"ls\")", {System, :shell}},
      {"def go, do: Port.open({:spawn, \"ls\"}, [])", Port},
      {"def go, do: :os.cmd(~c\"ls\")", {:os, :cmd}},
      {"def go, do: Node.list()", Node},
      {"def go, do: :erpc.call(:other@host, IO, :puts, [\"x\"])", :erpc},
      {"def go, do: :rpc.call(:other@host, IO, :puts, [\"x\"])", :rpc},
      {"def go, do: File.read(\"/etc/passwd\")", File},
      {"def go, do: :file.delete(~c\"/tmp/x\")", :file},
      {"def go, do: Application.put_env(:ouroboros, :forge_signer, Evil)",
       {Application, :put_env}},
      {"def go, do: :persistent_term.put(:key, :value)", :persistent_term},
      {"def go, do: :ets.give_away(:table, self(), :gift)", {:ets, :give_away}},
      {"def go, do: :erlang.load_nif(~c\"lib\", 0)", {:erlang, :load_nif}},
      {"def go, do: spawn(:other@host, IO, :puts, [\"x\"])", :remote_spawn},
      {"def go, do: spawn_link(:other@host, fn -> :ok end)", :remote_spawn},
      {"def go, do: :erlang.spawn(:other@host, IO, :puts, [\"x\"])", :remote_spawn},
      {"alias File, as: F\n  def go, do: F.read(\"/etc/passwd\")", {:alias, File}},
      {"import System\n  def go, do: cmd(\"ls\", [])", {:import, System}}
    ]

    for {body, construct} <- cases do
      assert {:error, {:forbidden_construct, ^construct, line}} = validate(@evil, body),
             "expected #{inspect(construct)} to be rejected in: #{body}"

      assert is_integer(line) and line > 0
    end

    # A local spawn names no node and is not the construct being refused.
    assert {:ok, _source} = validate(@evil, "def go, do: spawn(fn -> :ok end)")
    assert {:ok, _source} = validate(@evil, "def go, do: spawn(IO, :puts, [\"x\"])")
  end

  test "rejects protocol definitions and implementations" do
    protocol = """
    defmodule Ouroboros.Capability.Protocolish do
      defprotocol Shape do
        def area(shape)
      end
    end
    """

    assert {:error, {:forbidden_construct, :defprotocol, _line}} =
             Source.validate(source!(Ouroboros.Capability.Protocolish, protocol))

    implementation = """
    defmodule Ouroboros.Capability.Implish do
      defimpl String.Chars, for: Integer do
        def to_string(value), do: "\#{value}"
      end
    end
    """

    assert {:error, {:forbidden_construct, :defimpl, _line}} =
             Source.validate(source!(Ouroboros.Capability.Implish, implementation))
  end

  test "walks the test source with the same deny list" do
    assert {:ok, _source} =
             Source.validate(
               source!(
                 Ouroboros.Capability.Tested,
                 "defmodule Ouroboros.Capability.Tested do\n  def hello, do: :world\nend\n",
                 """
                 defmodule Ouroboros.Capability.TestedTest do
                   use ExUnit.Case, async: true

                   test "greets" do
                     assert Ouroboros.Capability.Tested.hello() == :world
                   end
                 end
                 """
               )
             )

    assert {:error, {:forbidden_construct, File, _line}} =
             Source.validate(
               source!(
                 Ouroboros.Capability.Tested,
                 "defmodule Ouroboros.Capability.Tested do\n  def hello, do: :world\nend\n",
                 """
                 defmodule Ouroboros.Capability.TestedTest do
                   use ExUnit.Case, async: true

                   test "exfiltrates" do
                     assert File.read!("/etc/passwd") != ""
                   end
                 end
                 """
               )
             )

    assert {:error, {:parse_failed, :test_source, _reason}} =
             Source.validate(
               source!(
                 Ouroboros.Capability.Tested,
                 "defmodule Ouroboros.Capability.Tested do\n  def hello, do: :world\nend\n",
                 "defmodule ["
               )
             )
  end

  test "rejection is parse-only: nothing the validator saw was ever defined" do
    # Every one of these would define, load, or execute something if validation were
    # implemented by compiling first and asking questions afterwards.
    hostile = [
      "def go, do: Code.eval_string(\"1 + 1\")",
      "@on_load :boot\n  def boot, do: :ok",
      "def go, do: File.rm_rf!(\"/\")"
    ]

    for body <- hostile do
      assert {:error, _reason} = validate(@evil, body)
    end

    assert :code.which(@evil) == :non_existing
    assert :code.get_object_code(@evil) == :error
    refute Code.ensure_loaded?(@evil)
    refute function_exported?(@evil, :go, 0)

    # The digest is checked too, so a record whose source was swapped after it was built
    # is refused before any of the above runs.
    source = source!(@evil, "defmodule #{inspect(@evil)} do\n  def go, do: :ok\nend\n")

    assert {:error, :source_digest_mismatch} =
             Source.validate(%{source | source: "defmodule Other do end"})
  end

  test "new/1 names the record and digests its source" do
    assert {:error, {:missing_attribute, :module}} = Source.new(source: "x", author: "agent")
    assert {:error, {:missing_attribute, :author}} = Source.new(module: @evil, source: "x")
    assert {:error, {:invalid_attribute, :test_source, 5}} = Source.new(attrs(test_source: 5))

    assert {:ok, source} = Source.new(attrs([]))
    assert source.sha256 == :crypto.hash(:sha256, source.source) |> Base.encode16(case: :lower)
    assert is_binary(source.id) and source.id != ""
    assert {:ok, _datetime, _offset} = DateTime.from_iso8601(source.created_at)
  end

  defp attrs(extra) do
    Keyword.merge(
      [module: @evil, source: "defmodule #{inspect(@evil)} do\nend\n", author: "agent"],
      extra
    )
  end

  defp validate(module, body) do
    source = """
    defmodule #{inspect(module)} do
      #{body}
    end
    """

    Source.validate(source!(module, source))
  end

  defp source!(module, source, test_source \\ nil) do
    {:ok, record} =
      Source.new(module: module, source: source, test_source: test_source, author: "test-agent")

    record
  end
end
