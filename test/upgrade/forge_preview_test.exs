defmodule Ouroboros.Upgrade.ForgePreviewTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Upgrade.Forge
  alias Ouroboros.Upgrade.Forge.Source

  @module Ouroboros.Capability.PreviewOnly
  @moduletag timeout: 300_000

  setup do
    on_exit(fn -> unload(@module) end)
    :ok
  end

  test "preview compiles and tests in the peer and loads nothing here" do
    {:ok, source} =
      Source.new(
        module: @module,
        author: "preview-test",
        source: capability_source(),
        test_source: capability_test_source()
      )

    assert {:ok, result} = Forge.preview(source)

    assert result.module == @module
    assert result.source_sha256 == source.sha256
    assert result.test_report.failures == 0
    assert result.test_report.total == 1
    assert result.test_report.ran
    assert :code.which(@module) == :non_existing
    refute Code.ensure_loaded?(@module)
  end

  test "a failing preview is a named build failure, still unloaded" do
    {:ok, source} =
      Source.new(
        module: @module,
        author: "preview-test",
        source: capability_source(),
        test_source: """
        defmodule Ouroboros.Capability.PreviewOnlyTest do
          use ExUnit.Case, async: false

          test "insists on the wrong answer" do
            assert Ouroboros.Capability.PreviewOnly.double(2) == 5
          end
        end
        """
      )

    assert {:error, {:build_failed, {:capability_tests_failed, summary}}} = Forge.preview(source)
    assert summary.failures == 1
    assert :code.which(@module) == :non_existing
  end

  defp capability_source do
    """
    defmodule #{inspect(@module)} do
      @vsn 1

      def double(n) when is_integer(n), do: n * 2
    end
    """
  end

  defp capability_test_source do
    """
    defmodule Ouroboros.Capability.PreviewOnlyTest do
      use ExUnit.Case, async: false

      test "doubles" do
        assert Ouroboros.Capability.PreviewOnly.double(21) == 42
      end
    end
    """
  end

  defp unload(module) do
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end
end
