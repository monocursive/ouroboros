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
  # The one top bar
  # ------------------------------------------------------------------------------------

  # Every route this surface serves, and the section each one is.
  @pages [
    {"/", :sessions},
    {"/s/interactive/some-session", :sessions},
    {"/new", :new},
    {"/settings", :settings},
    {"/status", :status},
    {"/audit", :audit},
    {"/audit/some-stream", :audit}
  ]

  describe "the top bar" do
    test "is on every page, with every destination on it", %{conn: conn} do
      # §3.1: the topbar existed only on the deck, `/new` and `/settings` carried a
      # "← Sessions" link and a theme toggle, `/status` and `/audit` carried a breadcrumb,
      # and `grep href="/status"` came back empty — three header treatments, none of which
      # reached the other spokes.
      for {path, _section} <- @pages do
        {:ok, _view, html} = live(conn, path)

        assert html =~ ~s(class="ouro-topbar"), "#{path} has no top bar"

        for {href, label} <- [
              {"/", "Sessions"},
              {"/new", "New session"},
              {"/settings", "Settings"},
              {"/audit", "Audit"},
              {"/status", "Status"}
            ] do
          assert html =~ ~s(href="#{href}"), "#{path}'s top bar does not link to #{href}"
          assert html =~ label, "#{path}'s top bar does not name #{label}"
        end

        assert html =~ "Ouroboros"
      end
    end

    test "marks the page being read, and marks exactly one element", %{conn: conn} do
      # `aria-current="page"` on two elements tells a screen-reader user there are two
      # current pages. The wordmark goes to `/` and deliberately carries none; a spoke of
      # a section is marked at its section, because that is where the reader is.
      for {path, section} <- @pages do
        {:ok, _view, html} = live(conn, path)

        href =
          case section do
            :sessions -> "/"
            :new -> "/new"
            :settings -> "/settings"
            :audit -> "/audit"
            :status -> "/status"
          end

        top = topbar(html)

        assert Regex.run(~r/href="#{Regex.escape(href)}"[^>]*aria-current="page"/, top) ||
                 Regex.run(~r/aria-current="page"[^>]*href="#{Regex.escape(href)}"/, top),
               "#{path} does not mark #{href} as the current page"

        marks = length(String.split(html, ~s(aria-current="page"))) - 1

        assert marks == 1,
               "#{path} marks #{marks} elements as the current page, not one"

        refute Regex.run(~r/ouro-wordmark[^>]*aria-current/, html),
               "#{path} marks the wordmark as the current page as well as the section"
      end
    end

    test "carries the connection pill on every page, as a live region", %{conn: conn} do
      # The pill's two halves are swapped by `.phx-connected` / `.phx-loading` in the
      # stylesheet, so the classes are the whole contract: a page that renders the element
      # without them would show both words at once.
      for {path, _section} <- @pages do
        {:ok, _view, html} = live(conn, path)

        assert html =~ ~s(class="ouro-pill")
        assert html =~ ~s(role="status")
        assert html =~ ~s(aria-live="polite")
        assert html =~ "ouro-pill-on"
        assert html =~ "ouro-pill-off"
      end
    end

    test "says nothing about machines or spend on a page that measured neither",
         %{conn: conn} do
      # Absent, not defaulted. The deck polls `runtime.status` and sums today's rows; the
      # spokes do neither, so they draw no presence row and no token total rather than an
      # empty one.
      for path <- ["/new", "/settings", "/status", "/audit"] do
        {:ok, _view, html} = live(conn, path)

        refute topbar(html) =~ "ouro-presence", "#{path} claims to know about machines"
        refute topbar(html) =~ "ouro-today", "#{path} claims to know today's spend"
      end

      {:ok, _view, deck} = live(conn, "/")
      assert topbar(deck) =~ "ouro-presence"
    end

    test "never spells an Erlang node name", %{conn: conn} do
      # Ground rule 6. `nonode@nohost` is the BEAM's word for "nobody named this machine",
      # not a machine name, and it reached the deck's presence row verbatim.
      for {path, _section} <- @pages do
        {:ok, _view, html} = live(conn, path)
        refute topbar(html) =~ "nonode@nohost", "#{path}'s top bar spells the node atom"
      end

      {:ok, _view, deck} = live(conn, "/")
      # A named BEAM (a distributed test module that ran earlier) is drawn by its label.
      if node() == :nonode@nohost do
        assert topbar(deck) =~ "this computer"
      else
        refute topbar(deck) =~ to_string(node())
      end
    end

    # PROOF F, inverted. Two machines in a fleet share a release name, so the bar must draw
    # the label its caller resolved rather than shorten the node itself.
    test "draws the caller's own word for a machine, not a second opinion" do
      html =
        render_component(&Layouts.topbar/1, %{
          machines: [
            %{name: "ouro@alpha", label: "the build box", connected?: true},
            %{name: "ouro@beta", label: "the spare", connected?: false}
          ]
        })

      hidden =
        ~r/class="ouro-visually-hidden">([^<]*)</
        |> Regex.scan(html, capture: :all_but_first)
        |> List.flatten()
        |> Enum.map(&String.trim/1)

      assert hidden == ["the build box", "the spare"]

      assert html =~ "the build box — connected"
      assert html =~ "the spare — not connected"
      refute html =~ "ouro@alpha"
    end

    test "falls back to the node's own host where a caller has no roster" do
      html =
        render_component(&Layouts.topbar/1, %{
          machines: [
            %{name: "ouro@alpha", connected?: true},
            %{name: "ouro@beta", connected?: false}
          ]
        })

      hidden =
        ~r/class="ouro-visually-hidden">([^<]*)</
        |> Regex.scan(html, capture: :all_but_first)
        |> List.flatten()
        |> Enum.map(&String.trim/1)

      # Two machines, two words — never "ouro" twice.
      assert hidden == ["alpha", "beta"]
    end

    test "renders standalone with no machines and no totals" do
      html = render_component(&Layouts.topbar/1, %{})

      assert html =~ "ouro-topbar"
      refute html =~ "ouro-presence"
      refute html =~ "ouro-today"
      refute html =~ ~s(aria-current="page")
    end
  end

  # The bar itself, cut out of whatever page it was drawn on.
  defp topbar(html) do
    [bar] = Regex.run(~r|<header class="ouro-topbar">.*?</header>|s, html)
    bar
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
      for path <- ["/", "/new", "/settings", "/status", "/audit"] do
        {:ok, _view, html} = live(conn, path)
        assert html =~ "data-ouro-theme", "#{path} has no theme toggle"
      end
    end

    test "is drawn once per page, not once per header treatment", %{conn: conn} do
      # W1.1 gave the spokes the shared top bar; their own headers gave up the copy of the
      # toggle they used to carry beside "← Sessions". Two toggles on one page would be
      # two controls for one preference, and `app.js` would leave whichever it reached
      # second disagreeing with the document.
      for path <- ["/", "/new", "/settings", "/status", "/audit"] do
        {:ok, _view, html} = live(conn, path)

        assert length(String.split(html, "data-ouro-theme")) == 2,
               "#{path} draws more than one theme toggle"
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

    # W1.1. The bell used to be the deck's alone, so a person filling in `/new` or reading
    # `/audit` got no signal that a session had started waiting
    # (`docs/design-qa/ui-review-2026-09-15.md` §3.1). It rings for the fleet, not for the
    # page, and it now sits in the one top bar every page renders.
    test "is on every page, because a session starts waiting wherever the reader is",
         %{conn: conn} do
      for path <- ["/", "/new", "/settings", "/status", "/audit"] do
        {:ok, _view, html} = live(conn, path)

        assert html =~ "data-ouro-bell", "#{path} offers no needs-you bell"

        assert length(String.split(html, "data-ouro-bell")) == 2,
               "#{path} draws more than one needs-you bell"
      end
    end

    # A bell that asked the browser for notification permission and then could never ring
    # would be the page promising something it cannot do. That every spoke can actually
    # ring is proven in `Ouroboros.Web.NeedsYouTest`, which drives the edge; what is
    # asserted here is only that each page holds the state the hook installs.
    test "every page that draws it has the machinery behind it", %{conn: conn} do
      for path <- ["/new", "/settings", "/status", "/audit"] do
        {:ok, view, _html} = live(conn, path)

        assert :sys.get_state(view.pid).socket.assigns
               |> Map.has_key?(:needs_you_announced),
               "#{path} draws a bell but has not attached the needs-you hook"
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
