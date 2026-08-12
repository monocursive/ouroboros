defmodule Ouroboros.Release.HandlerAdapterTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Release.{Artifact, HandlerAdapter, PackageStager, TestPackage}

  setup do
    path = TestPackage.create!()
    releases_dir = Path.dirname(path)
    previous = Application.get_env(:sasl, :releases_dir)
    Application.put_env(:sasl, :releases_dir, releases_dir)

    on_exit(fn ->
      File.rm_rf!(releases_dir)

      if is_nil(previous),
        do: Application.delete_env(:sasl, :releases_dir),
        else: Application.put_env(:sasl, :releases_dir, previous)
    end)

    {:ok, artifact} = Artifact.inspect_package(path)
    {:ok, binary} = Artifact.read_verified(artifact)
    {:ok, staged} = PackageStager.stage(HandlerAdapter.OTP, artifact.sha256, binary)

    %{artifact: artifact, binary: binary, releases_dir: releases_dir, staged: staged}
  end

  test "OTP alias is derived from the archive's actual top-level releases/name.rel", %{
    artifact: artifact,
    releases_dir: releases_dir,
    staged: staged
  } do
    assert {:ok, ~c"0.2.0"} =
             HandlerAdapter.OTP.unpack_release_with(
               String.to_charlist(staged.basename),
               fn otp_name ->
                 assert otp_name == ~c"ouroboros"
                 alias_path = Path.join(releases_dir, "ouroboros.tar.gz")
                 assert File.exists?(alias_path)

                 assert File.read!(alias_path)
                        |> then(&:crypto.hash(:sha256, &1))
                        |> Base.encode16(case: :lower) == artifact.sha256

                 {:ok, ~c"0.2.0"}
               end
             )

    refute File.exists?(Path.join(releases_dir, "ouroboros.tar.gz"))
    assert File.exists?(staged.path)
  end

  test "OTP alias creation fails closed when the required name already exists", %{
    releases_dir: releases_dir,
    staged: staged
  } do
    alias_path = Path.join(releases_dir, "ouroboros.tar.gz")
    File.write!(alias_path, "pre-existing package", [:binary, :sync])

    assert {:error, :release_package_alias_exists} =
             HandlerAdapter.OTP.unpack_release_with(
               String.to_charlist(staged.basename),
               fn _otp_name -> flunk("unpacker must not run when the OTP alias is occupied") end
             )

    assert File.read!(alias_path) == "pre-existing package"
    assert File.exists?(staged.path)
  end
end
