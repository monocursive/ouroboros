defmodule Ouroboros.Provider.Native.DesktopTest do
  # Not async: several tests flip the node-wide `:computer_use` flag, which is global state.
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Desktop
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.DesktopAct
  alias Ouroboros.Provider.Native.Tools.DesktopState

  setup do
    original = Application.get_env(:ouroboros, :computer_use)

    on_exit(fn ->
      # Restore config.exs's default rather than deleting it, so the shipped denylist and
      # bounds stay intact for the next test.
      if original == nil,
        do: Application.delete_env(:ouroboros, :computer_use),
        else: Application.put_env(:ouroboros, :computer_use, original)
    end)

    %{original: original}
  end

  # A real regular file on disk that stands in for the not-yet-built helper binary.
  defp fake_helper do
    path = Path.join(System.tmp_dir!(), "ouro-cu-helper-#{System.unique_integer([:positive])}")
    File.write!(path, "#!/bin/sh\n")
    on_exit(fn -> File.rm_rf(path) end)
    path
  end

  defp enable(helper_path, extra \\ []) do
    Application.put_env(
      :ouroboros,
      :computer_use,
      Keyword.merge([enabled: true, helper_path: helper_path], extra)
    )
  end

  describe "enabled?/0 — the honest predicate" do
    test "is false by default: the flag is off and no helper ships" do
      refute Desktop.enabled?()
      refute Desktop.helper_present?()
    end

    test "is false with the flag on but no helper on disk" do
      Application.put_env(:ouroboros, :computer_use, enabled: true, helper_path: "/nope/missing")
      refute Desktop.enabled?()
    end

    test "is false with a helper present but the flag off" do
      Application.put_env(:ouroboros, :computer_use, enabled: false, helper_path: fake_helper())
      refute Desktop.enabled?()
    end

    test "is true only when the flag is on and the helper exists on disk" do
      enable(fake_helper())
      assert Desktop.enabled?()
      assert Desktop.helper_present?()
    end

    test "OUROBOROS_COMPUTER_USE_HELPER overrides the configured path" do
      helper = fake_helper()
      System.put_env("OUROBOROS_COMPUTER_USE_HELPER", helper)
      on_exit(fn -> System.delete_env("OUROBOROS_COMPUTER_USE_HELPER") end)

      Application.put_env(:ouroboros, :computer_use, enabled: true, helper_path: "/still/missing")
      assert Desktop.helper_path() == helper
      assert Desktop.enabled?()
    end
  end

  describe "config bounds — a typo narrows, never widens" do
    test "a raised cap falls back to the shipped default" do
      Application.put_env(:ouroboros, :computer_use, max_image_bytes: 999_999_999)
      assert Desktop.config(:max_image_bytes) == 2 * 1024 * 1024

      Application.put_env(:ouroboros, :computer_use, max_nodes: 1_000_000)
      assert Desktop.config(:max_nodes) == 1_000
    end

    test "a lowered cap is honoured — narrowing is the operator's to make" do
      Application.put_env(:ouroboros, :computer_use, max_image_bytes: 512 * 1024)
      assert Desktop.config(:max_image_bytes) == 512 * 1024
    end

    test "a non-positive timeout falls back; a longer one is honoured" do
      Application.put_env(:ouroboros, :computer_use, state_timeout_ms: -5)
      assert Desktop.config(:state_timeout_ms) == 5_000

      Application.put_env(:ouroboros, :computer_use, state_timeout_ms: 30_000)
      assert Desktop.config(:state_timeout_ms) == 30_000
    end

    test "an out-of-range jpeg quality falls back" do
      Application.put_env(:ouroboros, :computer_use, jpeg_quality: 200)
      assert Desktop.config(:jpeg_quality) == 80

      Application.put_env(:ouroboros, :computer_use, jpeg_quality: 60)
      assert Desktop.config(:jpeg_quality) == 60
    end

    test "a malformed config keyword list falls back to every default" do
      Application.put_env(:ouroboros, :computer_use, "not a keyword list")
      assert Desktop.config(:enabled) == false
      assert Desktop.config(:max_frame_bytes) == 8 * 1024 * 1024
    end
  end

  describe "denied_app_ids/0 — a floor config cannot lower" do
    test "always includes ouro and the terminals, whatever config says" do
      ids = Desktop.denied_app_ids()

      for required <- ~w(com.ouroboros.desktop com.ouroboros.tui com.apple.Terminal
                         com.googlecode.iterm2 com.mitchellh.ghostty net.kovidgoyal.kitty) do
        assert required in ids, "expected #{required} in the denylist"
      end
    end

    test "includes the review's expanded ids (Warp, 1Password, Keychain, SecurityAgent)" do
      ids = Desktop.denied_app_ids()

      for required <- ~w(dev.warp.Warp-Stable org.alacritty com.github.wez.wezterm
                         co.zeit.hyper org.tabby com.1password.1password
                         com.apple.keychainaccess com.apple.SecurityAgent) do
        assert required in ids
      end
    end

    test "a shorter operator list cannot remove a baked id, only add" do
      Application.put_env(:ouroboros, :computer_use, denied_app_ids: ["com.example.custom"])
      ids = Desktop.denied_app_ids()

      assert "com.example.custom" in ids
      assert "com.apple.Terminal" in ids
      assert "com.ouroboros.desktop" in ids
    end

    test "a malformed denylist falls back to the baked floor" do
      Application.put_env(:ouroboros, :computer_use, denied_app_ids: "oops")
      assert "com.apple.Terminal" in Desktop.denied_app_ids()
    end

    test "config.exs's shipped denylist is a subset of the effective floor (anti-drift)", %{
      original: original
    } do
      shipped = if is_list(original), do: Keyword.get(original, :denied_app_ids, []), else: []
      assert shipped != [], "config.exs should ship a denied_app_ids list"
      assert MapSet.subset?(MapSet.new(shipped), MapSet.new(Desktop.denied_app_ids()))
    end
  end

  describe "app_alias/1 and denied_app?/1" do
    test "maps obvious names to bundle ids and passes unknowns through" do
      assert Desktop.app_alias("Safari") == "com.apple.Safari"
      assert Desktop.app_alias("Calculator") == "com.apple.calculator"
      assert Desktop.app_alias("Terminal") == "com.apple.Terminal"
      assert Desktop.app_alias("Some Random App") == "Some Random App"
      assert Desktop.app_alias("com.apple.Safari") == "com.apple.Safari"
      assert Desktop.app_alias(nil) == nil
    end

    test "denied_app? canonicalises a name before checking the denylist" do
      assert Desktop.denied_app?("Terminal")
      assert Desktop.denied_app?("com.apple.Terminal")
      refute Desktop.denied_app?("Safari")
      refute Desktop.denied_app?(nil)
    end
  end

  describe "status/0" do
    test "is clearly marked not-yet-wired in Phase 0" do
      status = Desktop.status()

      assert status.phase == 0
      assert status.wired == false
      assert status.note =~ "Phase 0 stub"
      assert status.enabled == false
      assert is_list(status.denied_app_ids)
      assert is_binary(status.helper_path)
    end
  end

  describe "specs/3 gating (D9, §5.1)" do
    test "off by default: both names absent even with a workspace" do
      names = Enum.map(Tools.specs(nil, nil, workspace: "/tmp"), & &1.name)
      refute "desktop_state" in names
      refute "desktop_act" in names
    end

    test "enabled + workspace: appended after the static tools, before MCP, in order" do
      enable(fake_helper())
      names = Enum.map(Tools.specs(nil, nil, workspace: "/tmp"), & &1.name)

      assert Enum.slice(names, -2, 2) == ["desktop_state", "desktop_act"]
      assert Enum.find_index(names, &(&1 == "desktop_state")) == 15
      assert Enum.find_index(names, &(&1 == "desktop_act")) == 16
    end

    test "enabled but no workspace: absent (host-local gate, same as MCP)" do
      enable(fake_helper())
      names = Enum.map(Tools.specs(nil, nil), & &1.name)
      refute "desktop_state" in names
      refute "desktop_act" in names
    end

    test "disallowed_tools hides one desktop tool by name" do
      enable(fake_helper())
      names = Enum.map(Tools.specs(nil, ["desktop_act"], workspace: "/tmp"), & &1.name)
      assert "desktop_state" in names
      refute "desktop_act" in names
    end

    test "lookup resolves the names only while enabled" do
      assert {:error, :unknown_tool} = Tools.lookup("desktop_state", nil, nil)
      assert {:error, :unknown_tool} = Tools.lookup("desktop_act", nil, nil)

      enable(fake_helper())
      assert {:ok, DesktopState} = Tools.lookup("desktop_state", nil, nil)
      assert {:ok, DesktopAct} = Tools.lookup("desktop_act", nil, nil)
    end

    test "every advertised desktop spec has a JSON Schema whose required fields exist" do
      enable(fake_helper())

      for spec <- Tools.specs(nil, nil, workspace: "/tmp"),
          spec.name in ["desktop_state", "desktop_act"] do
        assert %{"type" => "object", "properties" => properties} = spec.parameters
        assert is_map(properties)

        for required <- spec.parameters["required"] || [] do
          assert Map.has_key?(properties, required)
        end
      end
    end
  end

  describe "DesktopState.run/2 (Phase 0 stub)" do
    test "reports honestly that Computer Use is not enabled on this node" do
      assert {:ok, %{output: "computer use is not enabled on this node", is_error: true}} =
               DesktopState.run(%{include_image: true}, %{})
    end
  end

  describe "DesktopAct argument-validation table (§5.3)" do
    test "well-formed args reach the Phase 0 not-enabled stub" do
      assert {:ok, %{output: "computer use is not enabled on this node", is_error: true}} =
               DesktopAct.run(%{action: "click", element_index: 0}, %{})
    end

    test "click needs element_index or both x and y" do
      assert :ok = DesktopAct.validate_args(%{action: "click", element_index: 3})
      assert :ok = DesktopAct.validate_args(%{action: "click", x: 10, y: 20})
      assert {:error, message} = DesktopAct.validate_args(%{action: "click", x: 10})
      assert message =~ "element_index"

      assert {:ok, %{is_error: true, output: out}} = DesktopAct.run(%{action: "click"}, %{})
      assert out =~ "desktop_act click"
    end

    test "type needs non-empty text within 4 KiB" do
      assert :ok = DesktopAct.validate_args(%{action: "type", text: "hello"})
      assert {:error, _} = DesktopAct.validate_args(%{action: "type", text: ""})
      assert {:error, _} = DesktopAct.validate_args(%{action: "type"})

      big = String.duplicate("a", 4 * 1024 + 1)
      assert {:error, message} = DesktopAct.validate_args(%{action: "type", text: big})
      assert message =~ "4096 bytes"
    end

    test "key needs a valid key or combo" do
      assert :ok = DesktopAct.validate_args(%{action: "key", key: "Ctrl+L"})
      assert {:error, _} = DesktopAct.validate_args(%{action: "key", key: "Frobnicate"})
      assert {:error, _} = DesktopAct.validate_args(%{action: "key"})
    end

    test "scroll needs a direction" do
      assert :ok = DesktopAct.validate_args(%{action: "scroll", direction: "down"})
      assert {:error, message} = DesktopAct.validate_args(%{action: "scroll"})
      assert message =~ "direction"
      assert {:error, _} = DesktopAct.validate_args(%{action: "scroll", direction: "sideways"})
    end

    test "drag needs all four endpoints" do
      assert :ok =
               DesktopAct.validate_args(%{action: "drag", from_x: 1, from_y: 2, to_x: 3, to_y: 4})

      assert {:error, _} = DesktopAct.validate_args(%{action: "drag", from_x: 1, from_y: 2})
    end

    test "focus is well-formed with or without an explicit target (last-state fallback)" do
      assert :ok = DesktopAct.validate_args(%{action: "focus"})
      assert :ok = DesktopAct.validate_args(%{action: "focus", app: "Safari"})
    end

    test "an unknown action is refused, naming the closed enum" do
      assert {:error, message} = DesktopAct.validate_args(%{action: "teleport"})
      assert message =~ "click, type, key, scroll, drag, focus"
    end

    test "validate_args accepts string keys too, for direct callers" do
      assert :ok = DesktopAct.validate_args(%{"action" => "click", "element_index" => 1})
      assert {:error, _} = DesktopAct.validate_args(%{"action" => "type"})
    end
  end

  describe "DesktopAct.valid_key?/1 (§5.3 grammar)" do
    test "accepts named keys, letters, digits, function keys, and combos" do
      for key <- [
            "Enter",
            "return",
            "escape",
            "Tab",
            "space",
            "PageUp",
            "page-up",
            "page up",
            "Home",
            "End",
            "up",
            "F1",
            "F12",
            "a",
            "Z",
            "5",
            "Ctrl+L",
            "cmd+space",
            "Ctrl+Shift+T",
            "meta+a"
          ] do
        assert DesktopAct.valid_key?(key), "expected #{inspect(key)} to be valid"
      end
    end

    test "rejects a bare modifier, two keys, out-of-range function keys, and junk" do
      for key <- ["Ctrl", "a+b", "f13", "f0", "Frobnicate", "", "++", "ctrl+alt"] do
        refute DesktopAct.valid_key?(key), "expected #{inspect(key)} to be invalid"
      end

      refute DesktopAct.valid_key?(nil)
      refute DesktopAct.valid_key?(123)
    end
  end

  describe "stage_image/2 (§8.1)" do
    test "stages a jpeg: verified, written once at 0600 under session_dir/desktop, temp unlinked" do
      dir = session_dir()
      bytes = jpeg("a")
      temp = temp_image(bytes)

      assert {:ok, staged} =
               Desktop.stage_image(%{"path" => temp, "sha256" => sha(bytes)}, dir)

      assert staged.media_type == "image/jpeg"
      assert staged.sha256 == sha(bytes)
      assert staged.size == byte_size(bytes)
      assert staged.path == Path.join([dir, "desktop", sha(bytes) <> ".jpg"])
      assert File.read!(staged.path) == bytes
      assert {:ok, %File.Stat{mode: mode}} = File.stat(staged.path)
      assert Bitwise.band(mode, 0o777) == 0o600
      refute File.exists?(temp), "the helper temp is unlinked after staging"
    end

    test "stages a png" do
      dir = session_dir()
      bytes = png("p")
      temp = temp_image(bytes)

      assert {:ok, staged} = Desktop.stage_image(%{"path" => temp}, dir)
      assert staged.media_type == "image/png"
      assert staged.path == Path.join([dir, "desktop", sha(bytes) <> ".png"])
    end

    test "refuses bytes whose magic is not a jpeg or png" do
      dir = session_dir()
      temp = temp_image(<<"not an image at all">>)
      assert {:error, {:not_an_image, _}} = Desktop.stage_image(%{"path" => temp}, dir)
    end

    test "refuses a webp even though Attachments would accept it — desktop is jpeg/png only" do
      dir = session_dir()
      bytes = <<"RIFF", 0, 0, 0, 0, "WEBP", 0, 0>>
      temp = temp_image(bytes)
      assert {:error, {:not_an_image, "image/webp"}} = Desktop.stage_image(%{"path" => temp}, dir)
    end

    test "refuses an image over max_image_bytes" do
      Application.put_env(:ouroboros, :computer_use, max_image_bytes: 16)
      dir = session_dir()
      bytes = jpeg("big") <> :binary.copy(<<0>>, 64)
      temp = temp_image(bytes)
      assert {:error, :too_large} = Desktop.stage_image(%{"path" => temp}, dir)
    end

    test "refuses when the sha256 the helper claimed does not match the bytes" do
      dir = session_dir()
      temp = temp_image(jpeg("x"))

      assert {:error, :sha_mismatch} =
               Desktop.stage_image(%{"path" => temp, "sha256" => sha(jpeg("y"))}, dir)
    end

    test "refuses a missing path" do
      assert {:error, :missing_path} = Desktop.stage_image(%{}, session_dir())
    end

    test "evicts oldest files past max_snapshots_per_session" do
      Application.put_env(:ouroboros, :computer_use, max_snapshots_per_session: 2)
      dir = session_dir()

      for tag <- ["1", "2", "3", "4"] do
        bytes = jpeg(tag)
        assert {:ok, _} = Desktop.stage_image(%{"path" => temp_image(bytes)}, dir)
      end

      {:ok, names} = File.ls(Path.join(dir, "desktop"))
      assert length(names) == 2
    end
  end

  describe "DesktopState.run/2 observe (§5.2), injected helper runner" do
    test "renders the §5.2 text and returns one staged image" do
      dir = session_dir()
      bytes = jpeg("cap")
      temp = temp_image(bytes)
      raw = calculator_state(temp, sha(bytes))

      assert {:ok, result} =
               DesktopState.run(%{include_image: true}, %{
                 session_dir: dir,
                 desktop_runner: ok(raw)
               })

      refute result.is_error
      assert result.output =~ "app: com.apple.calculator (Calculator)"
      assert result.output =~ "nodes (2):"
      assert result.output =~ "image: 480x640 jpeg"
      assert result.output =~ "sha=#{sha(bytes)}"
      assert result.output =~ "focused_element: button \"2\""

      assert [image] = result.images
      assert image.media_type == "image/jpeg"
      assert image.sha256 == sha(bytes)
      assert File.exists?(image.path)
      assert Path.dirname(image.path) == Path.join(dir, "desktop")
    end

    test "include_image=false returns the tree only, no image line, no images" do
      dir = session_dir()
      raw = calculator_state(temp_image(jpeg("z")), sha(jpeg("z")))

      assert {:ok, result} =
               DesktopState.run(%{include_image: false}, %{
                 session_dir: dir,
                 desktop_runner: ok(raw)
               })

      assert result.images == []
      refute result.output =~ "image:"
      assert result.output =~ "nodes (2):"
    end

    test "a denied app is refused before any capture, naming the denylist" do
      runner = fn _method, _params, _timeout ->
        flunk("the helper must not be called for a denied app")
      end

      assert {:ok, result} =
               DesktopState.run(%{app: "Terminal"}, %{
                 session_dir: session_dir(),
                 desktop_runner: runner
               })

      assert result.is_error
      assert result.output =~ "denylist"
      assert result.images == []
    end

    test "a helper that is down is an honest in-band error, no image" do
      runner = fn "state", _params, _timeout -> {:error, :broken} end

      assert {:ok, result} =
               DesktopState.run(%{}, %{session_dir: session_dir(), desktop_runner: runner})

      assert result.is_error
      assert result.output =~ "not responding"
      assert result.images == []
    end

    test "a screenshot that cannot be staged still returns the tree, with a warning" do
      dir = session_dir()
      raw = calculator_state("/no/such/screenshot.jpg", "deadbeef")

      assert {:ok, result} =
               DesktopState.run(%{include_image: true}, %{
                 session_dir: dir,
                 desktop_runner: ok(raw)
               })

      refute result.is_error
      assert result.images == []
      assert result.output =~ "nodes (2):"
      assert result.output =~ "could not be staged"
    end

    test "no session directory is an honest error, no capture" do
      assert {:ok, result} =
               DesktopState.run(%{}, %{desktop_runner: ok(%{"app" => %{"id" => "x"}})})

      assert result.is_error
      assert result.output =~ "working directory"
    end

    test "off node with no injected runner reports not enabled" do
      assert {:ok,
              %{output: "computer use is not enabled on this node", is_error: true, images: []}} =
               DesktopState.run(%{include_image: true}, %{session_dir: session_dir()})
    end
  end

  describe "Tools.normalize_result/1 images seam (§8.1)" do
    test "carries a well-formed images list through unchanged" do
      part = %{path: "/p", media_type: "image/jpeg", sha256: "abc", size: 10}
      result = Tools.normalize_result({:ok, %{output: "x", is_error: false, images: [part]}})
      assert result.images == [part]
    end

    test "every other tool result shape has images: []" do
      assert Tools.normalize_result({:ok, %{output: "x"}}).images == []
      assert Tools.normalize_result({:error, :boom}).images == []
      assert Tools.normalize_result({:ok, %{not_output: 1}}).images == []
    end

    test "drops malformed image parts rather than passing them to the encoder" do
      result = Tools.normalize_result({:ok, %{output: "x", images: [%{path: "/p"}, "junk"]}})
      assert result.images == []
    end
  end

  # A jpeg/png distinguished only by its magic bytes; the body is derived from `tag` so two
  # captures differ and hash apart, which is all staging and eviction need.
  defp jpeg(tag), do: <<0xFF, 0xD8, 0xFF, 0xE0>> <> :crypto.hash(:sha256, tag) <> <<0xFF, 0xD9>>
  defp png(tag), do: <<137, 80, 78, 71, 13, 10, 26, 10>> <> :crypto.hash(:sha256, tag)

  defp sha(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

  defp temp_image(bytes) do
    path = Path.join(System.tmp_dir!(), "ouro-cu-temp-#{System.unique_integer([:positive])}")
    File.write!(path, bytes)
    on_exit(fn -> File.rm_rf(path) end)
    path
  end

  defp session_dir do
    dir = Path.join(System.tmp_dir!(), "ouro-cu-session-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end

  # A runner that answers `state` with a fixed raw payload and refuses anything else.
  defp ok(raw), do: fn "state", _params, _timeout -> {:ok, raw} end

  defp calculator_state(image_path, sha) do
    %{
      "app" => %{"id" => "com.apple.calculator", "name" => "Calculator"},
      "window" => %{
        "id" => "w_1",
        "title" => "Calculator",
        "focused" => true,
        "bounds" => %{"x" => 0, "y" => 0, "w" => 240, "h" => 320}
      },
      "image" => %{
        "path" => image_path,
        "mime" => "image/jpeg",
        "sha256" => sha,
        "width" => 480,
        "height" => 640,
        "coordinate_width" => 960,
        "coordinate_height" => 1280,
        "scale" => 2.0,
        "quality" => 80
      },
      "nodes" => [
        %{"index" => 0, "role" => "window", "name" => "Calculator", "actions" => []},
        %{"index" => 1, "role" => "button", "name" => "2", "actions" => ["click"]}
      ],
      "focused_element" => %{"index" => 1, "role" => "button", "name" => "2", "editable" => false},
      "readiness" => %{"screenshot" => "ok", "ax" => "ok", "input" => "ok"},
      "warnings" => []
    }
  end
end
