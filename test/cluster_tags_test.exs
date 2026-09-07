defmodule Ouroboros.Cluster.TagsTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Cluster.{Facts, Tags}
  alias Ouroboros.Gateway.Methods

  setup do
    root = Path.join(System.tmp_dir!(), "ouro-tags-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "fleet"))
    previous_data = Application.get_env(:ouroboros, :data_dir)

    previous_env =
      Map.new(
        ~w(OUROBOROS_FLEET_ID OUROBOROS_PROCESS_ID_HELPER OUROBOROS_NODE PATH),
        &{&1, System.get_env(&1)}
      )

    Application.put_env(:ouroboros, :data_dir, root)
    System.put_env("OUROBOROS_FLEET_ID", "00112233445566778899aabb")
    System.delete_env("OUROBOROS_NODE")

    profile = %{
      "schema" => 1,
      "fleet_id" => "00112233445566778899aabb",
      "machine" => "studio",
      "host" => "localhost",
      "node" => "ouro-studio@localhost",
      "role" => "core",
      "roster_revision" => 1,
      "members" => [
        %{"machine" => "studio", "host" => "localhost", "node" => "ouro-studio@localhost"}
      ],
      "tags" => []
    }

    path = Path.join([root, "fleet", "profile.json"])
    File.write!(path, Jason.encode!(profile))

    on_exit(fn ->
      Application.put_env(:ouroboros, :data_dir, previous_data)

      Enum.each(previous_env, fn {key, value} ->
        if value, do: System.put_env(key, value), else: System.delete_env(key)
      end)

      File.rm_rf!(root)
    end)

    %{root: root, path: path, profile: profile}
  end

  test "presence inventory never executes detected toolchains", %{root: root} do
    marker = Path.join(root, "executed")
    File.write!(Path.join(root, "xcodebuild"), "#!/bin/sh\ntouch '#{marker}'\n")
    File.chmod!(Path.join(root, "xcodebuild"), 0o700)
    System.put_env("PATH", root)
    assert Facts.local().toolchains == ["xcodebuild"]
    refute File.exists?(marker)
  end

  test "tag edits pass only fixed argv and target-local data to the profile writer", context do
    updated = Jason.encode!(Map.put(context.profile, "tags", ["xcode"]))
    helper = Path.join(context.root, "ouro")

    File.write!(helper, """
    #!/bin/sh
    [ "$#" = 5 ] && [ "$1" = fleet ] && [ "$2" = tag ] && [ "$3" = add ] && [ "$4" = -- ] && [ "$5" = xcode ] || exit 9
    printf '%s' '#{updated}' > "$OUROBOROS_DATA_DIR/fleet/profile.json"
    """)

    File.chmod!(helper, 0o700)
    System.put_env("OUROBOROS_PROCESS_ID_HELPER", helper)
    assert {:ok, ["xcode"]} = Tags.change(node(), "add", "xcode")
    assert {:ok, ["xcode"]} = Tags.change(node(), "list", nil)
    assert {:error, error} = Tags.change(node(), "add", "xcode;bad")
    assert error =~ "invalid fleet tag"
    assert {:ok, ["xcode"]} = Tags.change(node(), "list", nil)
  end

  test "remote removal can repair an invalid existing advisory tag", context do
    File.write!(context.path, Jason.encode!(Map.put(context.profile, "tags", ["--bad"])))
    helper = Path.join(context.root, "ouro")
    repaired = Jason.encode!(context.profile)

    File.write!(helper, """
    #!/bin/sh
    [ "$#" = 5 ] && [ "$1" = fleet ] && [ "$2" = tag ] && [ "$3" = remove ] && [ "$4" = -- ] && [ "$5" = --bad ] || exit 9
    printf '%s' '#{repaired}' > "$OUROBOROS_DATA_DIR/fleet/profile.json"
    """)

    File.chmod!(helper, 0o700)
    System.put_env("OUROBOROS_PROCESS_ID_HELPER", helper)
    assert %{tags: [], tags_error: error} = Facts.local()
    assert error =~ "--bad"
    assert {:ok, []} = Tags.change(node(), "remove", "--bad")
  end

  test "remote management has an operator gate and a bounded validated contract" do
    entry = Methods.table()["fleet.tags"]
    refute Methods.permits?(:read, entry)
    assert Methods.permits?(:operate, entry)
    assert entry.timeout == 15_000

    assert {:error, -32602, _} =
             Methods.invoke("fleet.tags", %{"machine" => "studio", "operation" => "invented"})

    System.delete_env("OUROBOROS_PROCESS_ID_HELPER")
    assert {:error, error} = Tags.local("add", "xcode")
    assert error =~ "restart it with ouro daemon"
  end
end
