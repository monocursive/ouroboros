defmodule Ouroboros.Provider.Native.DesktopTest do
  # Not async: several tests flip the node-wide `:computer_use` flag, which is global state.
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Desktop
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.DesktopAct
  alias Ouroboros.Provider.Native.Tools.DesktopState
  alias Ouroboros.Test.NativeModelScript

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
    test "is false when no helper is on disk, even if the flag would allow it" do
      Application.put_env(:ouroboros, :computer_use, enabled: true, helper_path: "/nope/missing")
      refute Desktop.enabled?()
      refute Desktop.helper_present?()
    end

    test "is false with a helper present when OUROBOROS_COMPUTER_USE is 0" do
      System.put_env("OUROBOROS_COMPUTER_USE", "0")
      on_exit(fn -> System.delete_env("OUROBOROS_COMPUTER_USE") end)
      Application.put_env(:ouroboros, :computer_use, helper_path: fake_helper())
      refute Desktop.enabled?()
      refute Desktop.flag_allows?()
    end

    test "is false when config(:enabled) is false even with a helper on disk" do
      Application.put_env(:ouroboros, :computer_use, enabled: false, helper_path: fake_helper())
      refute Desktop.enabled?()
      assert Desktop.helper_present?()
      assert Desktop.flag_allows?()
    end

    test "is true when a helper is on disk and the flag is not off" do
      enable(fake_helper())
      assert Desktop.flag_allows?()
      assert Desktop.enabled?()
      assert Desktop.helper_present?()
    end

    test "OUROBOROS_COMPUTER_USE_HELPER overrides the configured path" do
      helper = fake_helper()
      System.put_env("OUROBOROS_COMPUTER_USE_HELPER", helper)
      on_exit(fn -> System.delete_env("OUROBOROS_COMPUTER_USE_HELPER") end)

      Application.put_env(:ouroboros, :computer_use, helper_path: "/still/missing")
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
      assert Desktop.config(:enabled) == true
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
      assert Desktop.denied_app?("COM.APPLE.TERMINAL")
    end
  end

  describe "status/0" do
    test "reports the config posture and, with no ready helper, running: false" do
      Application.put_env(:ouroboros, :computer_use, helper_path: "/nope/missing")
      status = Desktop.status()

      assert status.enabled == false
      assert status.flag == true
      assert is_list(status.denied_app_ids)
      assert is_list(status.always_allowed_apps)
      assert is_binary(status.helper_path)
      assert status.helper_present == false
      assert status.running == false
      refute Map.has_key?(status, :doctor)
    end
  end

  describe "specs/3 gating (D9, §5.1)" do
    test "off when the helper is missing: both names absent even with a workspace" do
      Application.put_env(:ouroboros, :computer_use, helper_path: "/nope/missing")
      names = Enum.map(Tools.specs(nil, nil, workspace: "/tmp"), & &1.name)
      refute "desktop_state" in names
      refute "desktop_act" in names
    end

    test "enabled + workspace: desktop_state then desktop_act after static tools" do
      enable(fake_helper())
      names = Enum.map(Tools.specs(nil, nil, workspace: "/tmp"), & &1.name)

      assert "desktop_state" in names
      assert "desktop_act" in names
      assert Enum.find_index(names, &(&1 == "desktop_state")) == 15
      assert Enum.find_index(names, &(&1 == "desktop_act")) == 16
    end

    test "act_enabled false keeps observe but hides desktop_act" do
      enable(fake_helper(), act_enabled: false)
      names = Enum.map(Tools.specs(nil, nil, workspace: "/tmp"), & &1.name)
      assert "desktop_state" in names
      refute "desktop_act" in names
    end

    test "enabled but no workspace: absent (host-local gate, same as MCP)" do
      enable(fake_helper())
      names = Enum.map(Tools.specs(nil, nil), & &1.name)
      refute "desktop_state" in names
      refute "desktop_act" in names
    end

    test "disallowed_tools hides desktop_state by name" do
      enable(fake_helper())
      names = Enum.map(Tools.specs(nil, ["desktop_state"], workspace: "/tmp"), & &1.name)
      refute "desktop_state" in names
    end

    test "lookup resolves both desktop tools only while enabled" do
      Application.put_env(:ouroboros, :computer_use, helper_path: "/nope/missing")
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

  describe "DesktopState.run/2 when off" do
    test "reports honestly that Computer Use is not enabled on this node" do
      Application.put_env(:ouroboros, :computer_use, helper_path: "/nope/missing")

      assert {:ok, %{output: "computer use is not enabled on this node", is_error: true}} =
               DesktopState.run(%{include_image: true}, %{})
    end
  end

  describe "DesktopAct argument-validation table (§5.3)" do
    test "well-formed args without a helper report not enabled" do
      Application.put_env(:ouroboros, :computer_use, helper_path: "/nope/missing")

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

    test "a path outside $TMPDIR/ouro-cu is refused" do
      dir = session_dir()
      outside = Path.join(System.tmp_dir!(), "not-cu-#{System.unique_integer([:positive])}.jpg")
      File.write!(outside, jpeg("x"))
      on_exit(fn -> File.rm(outside) end)

      assert {:error, :path_outside_temp} = Desktop.stage_image(%{"path" => outside}, dir)
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
               DesktopState.run(%{app: "Calculator", include_image: true}, %{
                 session_dir: dir,
                 desktop_runner: ok(raw)
               })

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
               DesktopState.run(%{app: "Calculator", include_image: false}, %{
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

    test "untargeted observe is refused before capture" do
      runner = fn _method, _params, _timeout ->
        flunk("the helper must not be called without a target")
      end

      assert {:ok, result} =
               DesktopState.run(%{}, %{session_dir: session_dir(), desktop_runner: runner})

      assert result.is_error
      assert result.output =~ "untargeted"
    end

    test "a helper that is down is an honest in-band error, no image" do
      runner = fn "state", _params, _timeout -> {:error, :broken} end

      assert {:ok, result} =
               DesktopState.run(%{app: "Calculator"}, %{
                 session_dir: session_dir(),
                 desktop_runner: runner
               })

      assert result.is_error
      assert result.output =~ "not responding"
      assert result.images == []
    end

    test "a screenshot that cannot be staged still returns the tree, with a warning" do
      dir = session_dir()
      raw = calculator_state("/no/such/screenshot.jpg", "deadbeef")

      assert {:ok, result} =
               DesktopState.run(%{app: "Calculator", include_image: true}, %{
                 session_dir: dir,
                 desktop_runner: ok(raw)
               })

      refute result.is_error
      assert result.images == []
      assert result.output =~ "nodes (2):"
      assert result.output =~ "could not be staged"
    end

    test "resolved denylist refuses after capture, with no image" do
      dir = session_dir()
      raw = calculator_state(temp_image(jpeg("t")), sha(jpeg("t")))
      raw = put_in(raw, ["app", "id"], "com.apple.Terminal")

      assert {:ok, result} =
               DesktopState.run(%{window_id: "w_1"}, %{
                 session_dir: dir,
                 desktop_runner: ok(raw)
               })

      assert result.is_error
      assert result.output =~ "denylist"
      assert result.images == []
    end

    test "evaluated app mismatch is refused even when the call named no app" do
      dir = session_dir()
      raw = calculator_state(temp_image(jpeg("ev")), sha(jpeg("ev")))

      assert {:ok, result} =
               DesktopState.run(%{window_id: "w_1"}, %{
                 session_dir: dir,
                 desktop_runner: ok(raw),
                 desktop_evaluated_app: "com.apple.Safari"
               })

      assert result.is_error
      assert result.output =~ "resolved com.apple.calculator"
      assert result.output =~ "com.apple.Safari"
      assert result.images == []
    end

    test "claimed vs resolved mismatch is refused" do
      dir = session_dir()
      raw = calculator_state(temp_image(jpeg("m")), sha(jpeg("m")))

      assert {:ok, result} =
               DesktopState.run(%{app: "Safari"}, %{
                 session_dir: dir,
                 desktop_runner: ok(raw)
               })

      assert result.is_error
      assert result.output =~ "resolved com.apple.calculator"
      assert result.images == []
    end

    test "no session directory is an honest error, no capture" do
      assert {:ok, result} =
               DesktopState.run(%{}, %{desktop_runner: ok(%{"app" => %{"id" => "x"}})})

      assert result.is_error
      assert result.output =~ "working directory"
    end

    test "off node with no injected runner reports not enabled" do
      Application.put_env(:ouroboros, :computer_use, helper_path: "/nope/missing")

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

  describe "artifact/2" do
    test "serves a staged screenshot from the live pool, and from an existing named session dir" do
      bytes = jpeg("art")
      digest = sha(bytes)
      dir = session_dir()
      assert {:ok, _} = Desktop.stage_image(%{"path" => temp_image(bytes)}, dir)

      remember_last(dir, calculator_state(Path.join([dir, "desktop", digest <> ".jpg"]), digest))

      assert {:ok, fetched} = Desktop.artifact(digest)
      assert fetched.media_type == "image/jpeg"
      assert fetched.size == byte_size(bytes)
      assert Base.decode64!(fetched.bytes) == bytes

      assert {:error, :not_found} = Desktop.artifact("not-a-sha")
      assert {:error, :not_found} = Desktop.artifact(String.duplicate("a", 64))

      root = Path.join(System.tmp_dir!(), "ouro-cu-native-#{System.unique_integer([:positive])}")
      session_id = "native-testhosttag1-testrandtag12"
      named = Path.join(root, session_id)
      File.mkdir_p!(Path.join(named, "desktop"))

      File.cp!(
        Path.join([dir, "desktop", digest <> ".jpg"]),
        Path.join([named, "desktop", digest <> ".jpg"])
      )

      previous = Application.get_env(:ouroboros, :native_data_dir)
      Application.put_env(:ouroboros, :native_data_dir, root)

      on_exit(fn ->
        File.rm_rf(root)

        if previous == nil,
          do: Application.delete_env(:ouroboros, :native_data_dir),
          else: Application.put_env(:ouroboros, :native_data_dir, previous)
      end)

      assert {:ok, named_fetched} = Desktop.artifact(digest, session_id)
      assert Base.decode64!(named_fetched.bytes) == bytes

      missing_id = "native-testhosttag1-missingdir000"
      refute File.dir?(Path.join(root, missing_id))
      assert {:error, :not_found} = Desktop.artifact(digest, missing_id)
      refute File.dir?(Path.join(root, missing_id)), "artifact must not mkdir a guessed session"
    end
  end

  # A jpeg/png distinguished only by its magic bytes; the body is derived from `tag` so two
  # captures differ and hash apart, which is all staging and eviction need.
  defp jpeg(tag), do: <<0xFF, 0xD8, 0xFF, 0xE0>> <> :crypto.hash(:sha256, tag) <> <<0xFF, 0xD9>>
  defp png(tag), do: <<137, 80, 78, 71, 13, 10, 26, 10>> <> :crypto.hash(:sha256, tag)

  defp sha(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

  defp temp_image(bytes) do
    dir = Path.join(System.tmp_dir!(), "ouro-cu")
    File.mkdir_p!(dir)
    path = Path.join(dir, "temp-#{System.unique_integer([:positive])}.jpg")
    File.write!(path, bytes)
    on_exit(fn -> File.rm(path) end)
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
        "origin_x" => 100.0,
        "origin_y" => 120.0,
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

  describe "Desktop.act/2" do
    test "clicks by element_index against last state and sends the snapshot" do
      enable(fake_helper())
      dir = session_dir()
      raw = calculator_state(temp_image(jpeg("act")), sha(jpeg("act")))
      remember_last(dir, raw)

      {:ok, box} = Agent.start_link(fn -> nil end)

      runner = fn method, params, _timeout ->
        Agent.update(box, fn _ -> {method, params} end)

        {:ok,
         %{
           "ok" => true,
           "backend" => "ax",
           "app_id" => "com.apple.calculator",
           "window_id" => "w_1",
           "landing" => "focused role=AXButton editable=false name=2",
           "warnings" => []
         }}
      end

      assert {:ok, result} =
               DesktopAct.run(%{action: "click", element_index: 1}, %{
                 session_dir: dir,
                 desktop_runner: runner
               })

      refute result.is_error
      assert result.images == []
      assert result.output =~ "ok=true"
      assert result.output =~ "com.apple.calculator"

      assert {"act", params} = Agent.get(box, & &1)
      assert params["element"]["name"] == "2"
      assert params["target"]["app_id"] == "com.apple.calculator"
      assert params["target"]["window_id"] == "w_1"
      assert params["require_focus"] == true
      assert params["coordinate_space"]["origin_x"] == 100.0
      assert params["coordinate_space"]["origin_y"] == 120.0
      assert params["coordinate_space"]["scale"] == 2.0
    end

    test "a last state without :at is treated as stale" do
      enable(fake_helper())
      dir = session_dir()
      raw = calculator_state(temp_image(jpeg("noat")), sha(jpeg("noat")))

      Ouroboros.Provider.Native.Desktop.Pool.remember_state(
        Ouroboros.Provider.Native.Desktop.Pool,
        dir,
        %{state: raw}
      )

      runner = fn _method, _params, _timeout -> flunk("helper must not run for a stale act") end

      assert {:ok, result} =
               DesktopAct.run(%{action: "click", element_index: 1}, %{
                 session_dir: dir,
                 desktop_runner: runner
               })

      assert result.is_error
      assert result.output =~ "stale"
    end

    test "a stale last state is refused before the helper is called" do
      enable(fake_helper())
      dir = session_dir()
      raw = calculator_state(temp_image(jpeg("stale")), sha(jpeg("stale")))
      remember_last(dir, raw, at: System.system_time(:millisecond) - 60_000)

      runner = fn _method, _params, _timeout -> flunk("helper must not run for a stale act") end

      assert {:ok, result} =
               DesktopAct.run(%{action: "click", element_index: 1}, %{
                 session_dir: dir,
                 desktop_runner: runner
               })

      assert result.is_error
      assert result.output =~ "stale"
    end

    test "a claimed app that is not the last state is refused" do
      enable(fake_helper())
      dir = session_dir()
      raw = calculator_state(temp_image(jpeg("mis")), sha(jpeg("mis")))
      remember_last(dir, raw)

      runner = fn _method, _params, _timeout -> flunk("must not act on a mismatched app") end

      assert {:ok, result} =
               DesktopAct.run(%{action: "click", element_index: 1, app: "Safari"}, %{
                 session_dir: dir,
                 desktop_runner: runner
               })

      assert result.is_error
      assert result.output =~ "com.apple.calculator"
      assert result.output =~ "com.apple.Safari"
    end

    test "Terminal is denied by the named denylist before inject" do
      enable(fake_helper())
      dir = session_dir()

      assert {:ok, result} =
               DesktopAct.run(%{action: "focus", app: "Terminal"}, %{
                 session_dir: dir,
                 desktop_runner: fn _, _, _ -> flunk("denied") end
               })

      assert result.is_error
      assert result.output =~ "denylist"
      assert result.output =~ "com.apple.Terminal"
    end

    test "resolve_act returns the last state's app and refuses a mismatch" do
      dir = session_dir()
      raw = calculator_state(temp_image(jpeg("res")), sha(jpeg("res")))

      assert {:ok, "com.apple.Safari"} =
               Desktop.resolve_act(%{"action" => "focus", "app" => "Safari"}, dir)

      remember_last(dir, raw)

      assert {:ok, "com.apple.calculator"} =
               Desktop.resolve_act(%{"action" => "click"}, dir)

      assert {:error, message} =
               Desktop.resolve_act(%{"action" => "click", "app" => "Safari"}, dir)

      assert message =~ "com.apple.Safari"

      assert {:ok, "com.apple.Safari"} =
               Desktop.resolve_act(%{"action" => "focus", "app" => "Safari"}, dir)
    end

    test "sensitive_act? flags secret type text and secure fields" do
      assert Desktop.sensitive_act?(%{action: "type", text: "sk-live-secret"}, nil)
      refute Desktop.sensitive_act?(%{action: "type", text: "2"}, nil)

      dir = session_dir()

      raw =
        calculator_state(temp_image(jpeg("sec")), sha(jpeg("sec")))
        |> put_in(["nodes"], [
          %{
            "index" => 1,
            "role" => "AXSecureTextField",
            "name" => "Password",
            "actions" => []
          }
        ])

      remember_last(dir, raw)
      assert Desktop.sensitive_act?(%{action: "click", element_index: 1}, dir)
    end

    test "enrich_classified fills last-state app unless the call retargets without naming one" do
      dir = session_dir()
      raw = calculator_state(temp_image(jpeg("en")), sha(jpeg("en")))
      remember_last(dir, raw)

      filled =
        Desktop.enrich_classified(
          %{tool: "desktop_state", context: %{app: nil, desktop_action: "state"}},
          dir
        )

      assert filled.context.app == "com.apple.calculator"

      retarget =
        Desktop.enrich_classified(
          %{
            tool: "desktop_state",
            context: %{
              app: nil,
              desktop_action: "state",
              window_id: "w_other",
              title: nil
            }
          },
          dir
        )

      assert retarget.context.app == nil
    end
  end

  defp remember_last(dir, raw, opts \\ []) do
    at = Keyword.get(opts, :at, System.system_time(:millisecond))

    Ouroboros.Provider.Native.Desktop.Pool.remember_state(
      Ouroboros.Provider.Native.Desktop.Pool,
      dir,
      %{state: raw, at: at}
    )
  end

  describe "loop gate — desktop_state asks" do
    test "a :read desktop_state still raises approval_requested" do
      enable(fake_helper())

      root = Path.join(System.tmp_dir!(), "cu-ask-#{System.unique_integer([:positive])}")
      File.mkdir_p!(Path.join(root, "workspace"))
      File.mkdir_p!(Path.join(root, "session"))
      on_exit(fn -> File.rm_rf(root) end)

      {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)

      {model_spec, _agent} =
        NativeModelScript.start([
          [
            {:tool_call, %{id: "c1", name: "desktop_state", input: %{"app" => "Calculator"}}}
          ]
        ])

      test = self()

      loop = %Loop{
        emit: fn event -> send(test, {:event, event}) end,
        model_module: NativeModelScript,
        model_spec: model_spec,
        system: "system",
        scope: scope,
        session_dir: Path.join(root, "session"),
        session_id: "sess-1",
        provider_session_id: "native-x-y",
        turn_id: "turn-1",
        approval_mode: :ask,
        approval_timeout_ms: :infinity
      }

      spawn_link(fn -> Loop.run_turn(loop, "look") end)

      assert_receive {:event, %{type: :approval_requested, payload: payload}}, 5_000
      assert payload["tool_call"]["name"] == "desktop_state"
      assert payload["suggested_rule"]["pattern"] == "ComputerUse(app:com.apple.calculator)"
    end
  end
end
