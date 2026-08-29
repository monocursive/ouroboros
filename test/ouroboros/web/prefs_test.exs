defmodule Ouroboros.Web.PrefsTest do
  @moduledoc """
  `web.prefs.json`: what it may hold, how it is written, and the promise that reading it
  can never take a page down.

  The seeding half — that a stored default reaches `interactive.start` — is pinned in
  `Ouroboros.Web.Live.NewSessionTest` and again end to end in
  `Ouroboros.Web.Live.NewSessionLiveTest`, because "the value is in the struct" and "the
  value is in the request" are different claims and the second is the one that matters.
  """

  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Ouroboros.Web.Prefs

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ouroboros-web-prefs-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    {:ok, dir: dir}
  end

  defp write_raw!(dir, contents) do
    path = Prefs.path(dir)
    File.write!(path, contents)
    path
  end

  # ------------------------------------------------------------------------------------
  # Writing
  # ------------------------------------------------------------------------------------

  describe "writing" do
    test "keeps exactly the five keys the form states", %{dir: dir} do
      assert :ok =
               Prefs.write(dir, %{
                 "provider" => "claude_code",
                 "model" => "openai_codex:gpt-5.6-sol",
                 "workspace" => "/srv/ouroboros",
                 "sandbox_mode" => "workspace_write",
                 "reasoning_effort" => "high"
               })

      assert Prefs.read(dir) == %{
               "provider" => "claude_code",
               "model" => "openai_codex:gpt-5.6-sol",
               "workspace" => "/srv/ouroboros",
               "sandbox_mode" => "workspace_write",
               "reasoning_effort" => "high"
             }
    end

    test "writes only the keys that were actually stated", %{dir: dir} do
      # The whole point: a control the operator never touched must not become a default by
      # having been drawn.
      assert :ok = Prefs.write(dir, %{"provider" => "native"})

      assert Prefs.read(dir) == %{"provider" => "native"}
    end

    test "drops the session id, and anything else that is not one of the five", %{dir: dir} do
      assert :ok =
               Prefs.write(dir, %{
                 "id" => "sess-abcdef",
                 "provider" => "native",
                 "title" => "not a start parameter",
                 "turn_id" => "t-1"
               })

      stored = dir |> Prefs.path() |> File.read!() |> JSON.decode!()

      assert stored == %{"provider" => "native"}
      refute Map.has_key?(stored, "id")
    end

    test "writes nothing at all rather than an empty object", %{dir: dir} do
      assert :ok = Prefs.write(dir, %{})
      refute File.exists?(Prefs.path(dir))

      assert :ok = Prefs.write(dir, %{"id" => "sess-abcdef"})
      refute File.exists?(Prefs.path(dir))
    end

    test "the file is 0600 and a regular file", %{dir: dir} do
      # The token file's discipline. Nothing secret lives here, but it sits in a directory
      # beside two files that are, and one write discipline per directory is easier to keep
      # right than two.
      assert :ok = Prefs.write(dir, %{"provider" => "native"})

      assert {:ok, %File.Stat{mode: mode, type: :regular}} = File.lstat(Prefs.path(dir))
      assert Bitwise.band(mode, 0o777) == 0o600
    end

    test "leaves no temporary file behind", %{dir: dir} do
      assert :ok = Prefs.write(dir, %{"provider" => "native", "workspace" => "/srv"})

      assert File.ls!(dir) == ["web.prefs.json"]
    end

    test "a second write replaces the first entirely", %{dir: dir} do
      assert :ok = Prefs.write(dir, %{"provider" => "native", "reasoning_effort" => "high"})
      assert :ok = Prefs.write(dir, %{"provider" => "claude_code"})

      # Not a merge. The map handed in is the whole of what the operator stated this time,
      # and a key they deliberately left alone must not be resurrected from last time.
      assert Prefs.read(dir) == %{"provider" => "claude_code"}
    end

    test "refuses a value outside a closed vocabulary rather than storing it", %{dir: dir} do
      assert :ok =
               Prefs.write(dir, %{
                 "provider" => "native",
                 "sandbox_mode" => "danger_zone",
                 "reasoning_effort" => "maximum"
               })

      assert Prefs.read(dir) == %{"provider" => "native"}
    end

    test "trims, and treats blank as unstated", %{dir: dir} do
      assert :ok = Prefs.write(dir, %{"provider" => "  native  ", "workspace" => "   "})

      assert Prefs.read(dir) == %{"provider" => "native"}
    end

    test "a data directory that is not one is not a crash", %{dir: dir} do
      assert Prefs.write(nil, %{"provider" => "native"}) == :ok
      assert Prefs.write("", %{"provider" => "native"}) == :ok
      refute File.exists?(Prefs.path(dir))
    end
  end

  # ------------------------------------------------------------------------------------
  # Reading is total
  # ------------------------------------------------------------------------------------

  describe "reading is total" do
    test "an absent file is no defaults, and says nothing", %{dir: dir} do
      # First run is not a fault and does not deserve a log line.
      log = capture_log(fn -> assert Prefs.read(dir) == %{} end)
      assert log == ""
    end

    test "unparseable JSON is no defaults and one quiet line", %{dir: dir} do
      path = write_raw!(dir, "{\"provider\": ")

      log = capture_log(fn -> assert Prefs.read(dir) == %{} end)

      assert log =~ path
      assert log =~ "not readable JSON"
      refute log =~ "[error]"
    end

    test "JSON that is not an object is no defaults", %{dir: dir} do
      write_raw!(dir, "[\"native\"]")

      capture_log(fn -> assert Prefs.read(dir) == %{} end)
    end

    test "an object holding the wrong types drops those keys and keeps the rest", %{dir: dir} do
      write_raw!(dir, JSON.encode!(%{"provider" => "native", "workspace" => 42, "model" => nil}))

      assert Prefs.read(dir) == %{"provider" => "native"}
    end

    test "a stale vocabulary value is dropped rather than seeded", %{dir: dir} do
      # A `sandbox_mode` no adapter has heard of would seed a control that cannot draw it
      # and then travel to a plane that answers -32602 naming the parameter.
      write_raw!(dir, JSON.encode!(%{"provider" => "native", "sandbox_mode" => "read_write"}))

      assert Prefs.read(dir) == %{"provider" => "native"}
    end

    test "a file larger than the ceiling is refused without being parsed", %{dir: dir} do
      write_raw!(
        dir,
        JSON.encode!(%{"provider" => "native", "pad" => String.duplicate("x", 70_000)})
      )

      log = capture_log(fn -> assert Prefs.read(dir) == %{} end)
      assert log =~ "larger than"
    end

    test "a directory where the file should be is refused", %{dir: dir} do
      File.mkdir_p!(Prefs.path(dir))

      log = capture_log(fn -> assert Prefs.read(dir) == %{} end)
      assert log =~ "not a regular file"
    end

    test "a symlink is not followed", %{dir: dir} do
      elsewhere = Path.join(dir, "elsewhere.json")
      File.write!(elsewhere, JSON.encode!(%{"provider" => "native"}))
      File.ln_s!(elsewhere, Prefs.path(dir))

      # `lstat` sees the link itself, so this never reaches the target — the same posture
      # every private-file reader in this tree takes.
      log = capture_log(fn -> assert Prefs.read(dir) == %{} end)
      assert log =~ "not a regular file"
    end

    test "no data directory is no defaults" do
      assert Prefs.read(nil) == %{}
      assert Prefs.read("") == %{}
      assert Prefs.read("/nonexistent/ouroboros/data/dir") == %{}
    end
  end

  describe "the file's shape" do
    test "it lives at web.prefs.json in the data directory", %{dir: dir} do
      assert Prefs.path(dir) == Path.join(dir, "web.prefs.json")
    end

    test "the keys are the five interactive.start parameters a person chooses" do
      assert Prefs.keys() == [
               "provider",
               "model",
               "workspace",
               "sandbox_mode",
               "reasoning_effort"
             ]
    end
  end
end
