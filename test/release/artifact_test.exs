defmodule Ouroboros.Release.ArtifactTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Release.Artifact
  alias Ouroboros.Release.TestPackage

  test "inspects a release upgrade archive entirely offline" do
    path = TestPackage.create!()
    on_exit(fn -> File.rm_rf!(Path.dirname(path)) end)

    assert {:ok, artifact} = Artifact.inspect_package(path)
    assert artifact.release_name == "ouroboros"
    assert artifact.version == "0.2.0"
    assert artifact.package_name == "ouroboros-0.2.0"
    assert artifact.id == "otp-release-sha256:" <> artifact.sha256

    assert [upgrade] = artifact.relup.upgrades
    assert upgrade.version == "0.1.0"
    assert upgrade.instruction_count == 1
    assert upgrade.point_of_no_return?
    refute upgrade.restart?

    assert [%{version: "0.2.0"}] = artifact.appups
    assert :ok = Artifact.revalidate(artifact)
  end

  test "rejects traversal members and inconsistent release metadata" do
    traversal = TestPackage.create!(extra_entries: [{"../escape", "not extracted"}])
    on_exit(fn -> File.rm_rf!(Path.dirname(traversal)) end)
    assert {:error, :unsafe_archive_member} = Artifact.inspect_package(traversal)

    mismatch = TestPackage.create!(boot_version: "9.9.9")
    on_exit(fn -> File.rm_rf!(Path.dirname(mismatch)) end)
    assert {:error, :boot_release_version_mismatch} = Artifact.inspect_package(mismatch)
  end

  test "rejects package extensions that release_handler will not resolve" do
    path = TestPackage.create!()
    tgz = Path.rootname(path, ".gz")
    File.rename!(path, tgz)
    on_exit(fn -> File.rm_rf!(Path.dirname(tgz)) end)

    assert {:error, :release_package_must_end_in_tar_gz} = Artifact.inspect_package(tgz)
  end

  test "revalidation retains the exact inspection policy" do
    path = TestPackage.create!(include_relup: false)
    on_exit(fn -> File.rm_rf!(Path.dirname(path)) end)

    assert {:error, :missing_relup} = Artifact.inspect_package(path)
    assert {:ok, artifact} = Artifact.inspect_package(path, require_relup: false)
    assert artifact.inspection_policy[:require_relup] == false
    assert :ok = Artifact.revalidate(artifact)
  end

  test "rejects appup files whose path or target version does not match the release" do
    unexpected_path =
      TestPackage.create!(
        extra_entries: [
          {"lib/foreign-1.0.0/ebin/foreign.appup", valid_appup("1.0.0")}
        ]
      )

    on_exit(fn -> File.rm_rf!(Path.dirname(unexpected_path)) end)

    assert {:error, {:unexpected_appup_path, "lib/foreign-1.0.0/ebin/foreign.appup"}} =
             Artifact.inspect_package(unexpected_path)

    wrong_version =
      TestPackage.create!(
        extra_entries: [
          {"lib/kernel-11.0.2/ebin/kernel.appup", valid_appup("99.0.0")}
        ]
      )

    on_exit(fn -> File.rm_rf!(Path.dirname(wrong_version)) end)

    assert {:error,
            {:appup_version_mismatch, "lib/kernel-11.0.2/ebin/kernel.appup", "11.0.2", "99.0.0"}} =
             Artifact.inspect_package(wrong_version)
  end

  defp valid_appup(version) do
    {:ok, term} =
      Ouroboros.Release.Metadata.appup(
        version,
        [
          {"0.1.0", "upgrade", [{:load_module, Ouroboros}]}
        ],
        []
      )

    Ouroboros.Release.Metadata.encode(term)
  end
end
