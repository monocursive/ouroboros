defmodule Ouroboros.DataDirTest do
  use ExUnit.Case, async: true

  alias Ouroboros.DataDir

  @moduletag :tmp_dir

  describe "the durable leaf boundary" do
    test "creates a missing leaf at mode 0700", %{tmp_dir: parent} do
      data_dir = Path.join(parent, "durable") <> "/"

      assert :ok = DataDir.ensure_private!(data_dir)

      stat = File.lstat!(data_dir, time: :posix)
      assert stat.type == :directory
      assert Bitwise.band(stat.mode, 0o777) == 0o700
    end

    test "refuses a broad existing leaf without chmodding or mutating it", %{tmp_dir: parent} do
      data_dir = Path.join(parent, "broad")
      File.mkdir!(data_dir)
      File.chmod!(data_dir, 0o755)
      File.write!(Path.join(data_dir, "sentinel"), "unchanged")

      error = assert_raise RuntimeError, fn -> DataDir.ensure_private!(data_dir) end

      assert error.message =~ "mode-0700 durable data directory"
      assert error.message =~ "will not chmod or replace"
      assert File.read!(Path.join(data_dir, "sentinel")) == "unchanged"
      assert Bitwise.band(File.stat!(data_dir).mode, 0o777) == 0o755
      assert File.ls!(data_dir) == ["sentinel"]
    end

    test "refuses a symlinked leaf without touching its target", %{tmp_dir: parent} do
      target = Path.join(parent, "target")
      data_dir = Path.join(parent, "durable")
      File.mkdir!(target)
      File.chmod!(target, 0o700)
      File.write!(Path.join(target, "sentinel"), "unchanged")
      File.ln_s!(target, data_dir)

      error = assert_raise RuntimeError, fn -> DataDir.ensure_private!(data_dir) end

      assert error.message =~ "mode-0700 durable data directory"
      assert File.read!(Path.join(target, "sentinel")) == "unchanged"
      assert File.ls!(target) == ["sentinel"]
      assert File.lstat!(data_dir).type == :symlink
    end
  end

  describe "a configured directory" do
    test "is normalized consistently with the gateway and must be absolute" do
      assert DataDir.resolve!("/srv/ouroboros", "/xdg", "/home/o") == "/srv/ouroboros"
      assert DataDir.resolve!("  /srv/ouroboros  ", nil, nil) == "/srv/ouroboros"
      assert DataDir.configured!("\t/srv/ouroboros\n") == "/srv/ouroboros"

      # The XDG variables are not consulted at all once the operator named a directory.
      assert DataDir.resolve!("/srv/ouroboros", nil, nil) == "/srv/ouroboros"

      assert_raise RuntimeError, ~r/OUROBOROS_DATA_DIR/, fn ->
        DataDir.resolve!("relative/state", "/xdg", "/home/o")
      end

      assert_raise RuntimeError, ~r/nonblank absolute durable directory/, fn ->
        DataDir.configured!("  relative/gateway  ")
      end
    end

    test "is absent when it is blank, which is what the default is for" do
      assert DataDir.resolve!("", "/xdg", "/home/o") == "/xdg/ouroboros"
      assert DataDir.resolve!("   ", "/xdg", "/home/o") == "/xdg/ouroboros"
      assert DataDir.configured!(nil) == nil
      assert DataDir.configured!(" \t\n") == nil
    end
  end

  describe "the default" do
    # These expectations are the cross-language contract with `Paths::discover` in
    # `tui/src/runtime.rs`: the client derives the same path and then reads gateway.json
    # out of it, so a change here is a change to what the client can find.
    test "follows XDG_DATA_HOME when it is an absolute path" do
      assert DataDir.resolve!(nil, "/var/lib/xdg", "/home/o") == "/var/lib/xdg/ouroboros"
      assert DataDir.resolve!(nil, "/var/lib/xdg/", "/home/o") == "/var/lib/xdg/ouroboros"
    end

    test "falls back to HOME when XDG_DATA_HOME is unset, blank, or relative" do
      assert DataDir.resolve!(nil, nil, "/home/o") == "/home/o/.local/share/ouroboros"
      assert DataDir.resolve!(nil, "", "/home/o") == "/home/o/.local/share/ouroboros"
      assert DataDir.resolve!(nil, "   ", "/home/o") == "/home/o/.local/share/ouroboros"

      # The XDG basedir specification says a relative value is invalid and must be
      # ignored, and the client ignores it the same way rather than refusing.
      assert DataDir.resolve!(nil, "share", "/home/o") == "/home/o/.local/share/ouroboros"

      assert DataDir.resolve!(nil, nil, "/home/o/") == "/home/o/.local/share/ouroboros"
    end

    test "cannot be derived with no home, and says so rather than guessing" do
      error = assert_raise RuntimeError, fn -> DataDir.resolve!(nil, nil, nil) end

      assert error.message =~ "OUROBOROS_DATA_DIR"
      assert error.message =~ "HOME"

      assert_raise RuntimeError, ~r/HOME/, fn -> DataDir.resolve!(nil, "", "  ") end

      assert_raise RuntimeError, ~r/not an absolute path/, fn ->
        DataDir.resolve!(nil, nil, "o")
      end
    end
  end
end
