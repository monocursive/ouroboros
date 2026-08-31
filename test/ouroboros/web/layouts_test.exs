defmodule Ouroboros.Web.LayoutsTest do
  @moduledoc """
  The document shell and the two chrome toggles that sit in every page's top row.

  ## What is proven here, and what is not

  Half of the theme and all of the bell live in `app.js`, and there is no JavaScript
  toolchain in this repo to run it in — the whole point of W0's asset decision. So this file
  proves the halves that are reachable from the BEAM:

    * the pre-paint script is in the document, is not deferred, and comes before the
      stylesheet;
    * both toggles render, on every page that claims them, as static markup with the
      `data-*` attributes `app.js` looks for;
    * the two files agree on the `localStorage` keys, asserted by reading `app.js` as text
      — a drift there would silently write a preference nothing reads back.

  **Unverified by this suite:** that clicking either toggle does anything. `localStorage`
  round-tripping, the `data-theme` flip, the Notification permission prompt, the Page
  Visibility check and the notification itself are all `app.js`, and nothing in this tree
  executes it. They were reasoned about, not run.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Layouts

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("y", 40)
  @cookie "_ouroboros_web"

  @app_js File.read!("priv/static/web/app.js")

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ouroboros-web-layouts-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)
    on_exit(fn -> File.rm_rf(dir) end)

    config = Config.new!(data_dir: dir, scope: :operate)
    start_supervised!({Ouroboros.Web, config: config, server: false})

    {:ok, conn: signed_in()}
  end

  defp signed_in do
    conn = get(build_conn(), "/auth?token=#{@token}")
    put_req_cookie(build_conn(), @cookie, conn.resp_cookies[@cookie].value)
  end

  # ------------------------------------------------------------------------------------
  # The pre-paint script
  # ------------------------------------------------------------------------------------

  describe "the theme script" do
    test "reads the stored choice and stamps it on the document element" do
      script = Layouts.theme_script()

      assert script =~ ~s|localStorage.getItem("ouroboros:theme")|
      assert script =~ ~s|setAttribute("data-theme"|
    end

    test "accepts only the two words that name a theme" do
      # A key holding anything else — a half-written value, something another tool put
      # there — must leave the document alone rather than stamp it verbatim.
      assert Layouts.theme_script() =~ ~s{choice === "light" || choice === "dark"}
    end

    test "survives a browser that refuses storage outright" do
      # `localStorage` does not merely come back empty in a private window or under a
      # block-site-data setting: the accessor throws. Unguarded, this script would take the
      # rest of the page's head with it.
      assert Layouts.theme_script() =~ "try {"
      assert Layouts.theme_script() =~ "catch (error)"
    end

    test "is inline, is not deferred, and runs before the stylesheet", %{conn: conn} do
      html = conn |> get("/") |> html_response(200)

      [head] = Regex.run(~r|<head>(.*?)</head>|s, html, capture: :all_but_first)

      assert head =~ ~s|setAttribute("data-theme"|,
             "the pre-paint script is not in the document head"

      script_at = :binary.match(head, ~s|setAttribute("data-theme"|) |> elem(0)
      css_at = :binary.match(head, "/web/app.css") |> elem(0)

      assert script_at < css_at,
             "the theme script runs after the stylesheet; the page will paint dark first"

      # Deferred, it would run after first paint, which is the entire failure it exists to
      # prevent. The three real script files are deferred; this one must not be.
      inline = Regex.run(~r|<script>(?:(?!</script>).)*data-theme.*?</script>|s, head)
      assert inline, "the theme script is not an inline <script>"
      refute hd(inline) =~ "defer"
    end

    test "the layout and app.js name the same storage key" do
      assert @app_js =~ ~s|"#{Layouts.theme_storage_key()}"|,
             "app.js does not read the key the layout writes"
    end
  end

  # ------------------------------------------------------------------------------------
  # The toggles as markup
  # ------------------------------------------------------------------------------------

  describe "the theme toggle" do
    test "renders as an icon-only button app.js can find" do
      html = render_component(&Layouts.theme_toggle/1, %{})

      assert html =~ "data-ouro-theme"
      assert html =~ ~s|class="ouro-icon-button"|
      assert html =~ ~s|type="button"|
      assert html =~ "<svg"
    end

    test "carries a label, because a glyph on its own names nothing" do
      html = render_component(&Layouts.theme_toggle/1, %{})

      assert html =~ ~s|aria-label="Switch to the light theme"|
      assert html =~ ~s|aria-pressed="false"|
      assert html =~ ~s|aria-hidden="true"|
    end

    test "carries no server state at all" do
      # Two renders, byte for byte identical. That is what makes it survivable across
      # LiveView patches without `phx-update="ignore"`: the server has no opinion to
      # overwrite what `app.js` set.
      assert render_component(&Layouts.theme_toggle/1, %{}) ==
               render_component(&Layouts.theme_toggle/1, %{})
    end

    test "is on every operator page", %{conn: conn} do
      for path <- ["/", "/machines", "/new", "/settings"] do
        {:ok, _view, html} = live(conn, path)
        assert html =~ "data-ouro-theme", "#{path} has no theme toggle"
      end
    end
  end

  describe "the needs-you bell" do
    test "renders unpressed, always" do
      html = render_component(&Layouts.bell_toggle/1, %{})

      assert html =~ "data-ouro-bell"
      assert html =~ ~s|aria-pressed="false"|
    end

    test "is born off on every load" do
      # Enabling this asks the browser for a permission. A control that restored "on" from
      # storage would be claiming a channel it has not re-checked, and `app.js` re-checks
      # the permission on every announce for the same reason.
      refute render_component(&Layouts.bell_toggle/1, %{}) =~ ~s|aria-pressed="true"|
    end

    test "is on the deck and nowhere else", %{conn: conn} do
      {:ok, _view, deck} = live(conn, "/")
      assert deck =~ "data-ouro-bell"

      for path <- ["/machines", "/new", "/settings"] do
        {:ok, _view, html} = live(conn, path)

        refute html =~ "data-ouro-bell",
               "#{path} offers a needs-you bell, but has no needs-you group to ring for"
      end
    end

    test "app.js reads the bell's own storage key and the Notification API defensively" do
      assert @app_js =~ ~s|"ouroboros:notify"|

      # The three rules the server cannot enforce, each present in the file that can.
      assert @app_js =~ "document.hidden", "app.js does not check Page Visibility"
      assert @app_js =~ ~s|permission !== "granted"|, "app.js does not re-check permission"
      assert @app_js =~ "rung[", "app.js does not remember which requests already rang"
    end
  end
end
