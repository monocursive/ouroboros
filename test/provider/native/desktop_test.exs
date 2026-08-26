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
end
