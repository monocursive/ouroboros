defmodule Ouroboros.DataDirTest do
  use ExUnit.Case, async: true

  alias Ouroboros.DataDir

  describe "a configured directory" do
    test "is used as given and must be absolute" do
      assert DataDir.resolve!("/srv/ouroboros", "/xdg", "/home/o") == "/srv/ouroboros"

      # The XDG variables are not consulted at all once the operator named a directory.
      assert DataDir.resolve!("/srv/ouroboros", nil, nil) == "/srv/ouroboros"

      assert_raise RuntimeError, ~r/OUROBOROS_DATA_DIR/, fn ->
        DataDir.resolve!("relative/state", "/xdg", "/home/o")
      end
    end

    test "is absent when it is blank, which is what the default is for" do
      assert DataDir.resolve!("", "/xdg", "/home/o") == "/xdg/ouroboros"
      assert DataDir.resolve!("   ", "/xdg", "/home/o") == "/xdg/ouroboros"
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
