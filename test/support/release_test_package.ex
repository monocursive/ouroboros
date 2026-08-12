defmodule Ouroboros.Release.TestPackage do
  alias Ouroboros.Release.Metadata

  def create!(opts \\ []) do
    root =
      Path.join(System.tmp_dir!(), "ouroboros-release-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)
    path = Path.join(root, "ouroboros-0.2.0.tar.gz")

    {:ok, rel} =
      Metadata.rel("ouroboros", "0.2.0", [
        {:kernel, "11.0.2"},
        {:stdlib, "7.0.1"},
        {:sasl, "4.4"},
        {:ouroboros, "0.2.0"}
      ])

    {:ok, relup} =
      Metadata.relup("0.2.0", [{"0.1.0", "upgrade", [:point_of_no_return]}], [])

    {:ok, appup} =
      Metadata.appup("0.2.0", [{"0.1.0", "upgrade", [{:load_module, Ouroboros}]}], [])

    boot_version = Keyword.get(opts, :boot_version, "0.2.0")

    boot =
      :erlang.term_to_binary({:script, {~c"ouroboros", String.to_charlist(boot_version)}, []})

    rel_binary = Metadata.encode(rel)

    entries = [
      {~c"releases/ouroboros.rel", rel_binary},
      {~c"releases/0.2.0/ouroboros.rel", rel_binary},
      {~c"releases/0.2.0/start.boot", boot},
      {~c"lib/ouroboros-0.2.0/ebin/ouroboros.appup", Metadata.encode(appup)}
    ]

    entries =
      if Keyword.get(opts, :include_relup, true),
        do: entries ++ [{~c"releases/0.2.0/relup", Metadata.encode(relup)}],
        else: entries

    extra_entries =
      opts
      |> Keyword.get(:extra_entries, [])
      |> Enum.map(fn {name, binary} -> {String.to_charlist(name), binary} end)

    :ok = :erl_tar.create(String.to_charlist(path), entries ++ extra_entries, [:compressed])
    path
  end
end
