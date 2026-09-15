defmodule Ouroboros.Web.StylesheetTest do
  @moduledoc """
  What can be asserted about `priv/static/web/app.css` without a browser.

  This file exists because of a defect a passing suite could not see. A merge left
  `.ouro-new-refusal-detail` without its closing brace and the following section's comment
  without its opening `/*`, and CSS error recovery answered by swallowing **every rule from
  that point to the end of the file** as one malformed declaration. Everything after that
  point was dead — links rendered in the browser's own blue-then-purple — and nothing in
  584 passing tests noticed, because every one of them asserted on markup.

  So the first two tests here are structural: braces balance, comments close. They are worth
  more than anything else in the file.

  The rest is the design rules the stylesheet's own header states, asserted rather than
  trusted:

    * rule 1 — `--attention-green` means "a human is needed here" and never anything else;
    * every colour goes through a token, so a theme can actually change it;
    * every colour token has a light counterpart, because half a palette is not a theme.
  """

  use ExUnit.Case, async: true

  @css File.read!("priv/static/web/app.css")

  # ------------------------------------------------------------------------------------
  # Structure
  # ------------------------------------------------------------------------------------

  describe "the file parses" do
    test "every comment that opens is closed" do
      # A stray `*/` with no `/*` is what turned a section header into part of a
      # declaration body. Counting is enough to catch it and cannot itself be wrong.
      assert length(String.split(@css, "/*")) == length(String.split(@css, "*/")),
             "app.css has an unbalanced comment; a section header has probably lost its /*"
    end

    test "every block that opens is closed, and none closes early" do
      {depth, unopened} =
        @css
        |> strip_comments()
        |> String.graphemes()
        |> Enum.reduce({0, 0}, fn
          "{", {depth, unopened} -> {depth + 1, unopened}
          "}", {0, unopened} -> {0, unopened + 1}
          "}", {depth, unopened} -> {depth - 1, unopened}
          _other, acc -> acc
        end)

      assert unopened == 0, "app.css closes #{unopened} block(s) that were never opened"

      assert depth == 0,
             "app.css leaves #{depth} block(s) open; every rule after the first one is " <>
               "swallowed by CSS error recovery and renders as nothing"
    end

    test "a section is a section rather than part of the rule above it" do
      # The exact regression, named: a rule after the unterminated one is only reachable
      # if the block before it terminated.
      assert rule_for(".ouro-new-refusal-detail"),
             ".ouro-new-refusal-detail has no rule of its own"

      assert rule_for(".ouro-new-back"), ".ouro-new-back has no rule of its own"
    end

    test "no component class is defined by two different sections" do
      # The second defect the repair above uncovered. `.ouro-chip` was claimed by two
      # sections at once, and because the later block came later in the file it would have
      # quietly restyled the earlier component — small-caps, a larger face, a grid
      # placement — the moment the section became reachable. Nobody had seen it, because
      # the section had never been reachable.
      #
      # Sharing a class between two components is a decision; arriving at it by accident, in
      # two sections written weeks apart, is this bug.
      #
      # The unit is the **page section** — the `/* ==== */` banners this file is organised
      # by — not the individual rule. A class named twice inside one section is a component
      # being refined by the slice that owns it: `.ouro-composer-input` gets its box in the
      # focused-pane block and its behaviour in the composer block, and the media query at
      # the end of the deck restates three layout classes on purpose. All of that is one
      # author working on one thing. The same class claimed by two *different* sections is
      # two authors who did not know about each other, which is what happened here.
      # Split *before* stripping comments — the section banners are comments, and stripping
      # first leaves one undifferentiated section in which nothing can collide. (Which is
      # exactly what the first version of this test did, and it passed against a stylesheet
      # with the collision put back on purpose.)
      #
      # The `@media` blocks are lifted out first. What this test protects is where a
      # component is *defined*; a responsive override is not a definition, and since W1.9
      # every breakpoint is declared exactly once (see "the breakpoints" below) it
      # necessarily restates classes belonging to several component sections. That is one
      # author doing responsive work — the case this test's own docstring already exempts
      # for the narrow-view block — not two authors who did not know about each other.
      #
      # **Not covered by this test:** a collision between two rules that are both inside
      # `@media` blocks. Nor was it before W1.9, except by the accident of both rules
      # happening to sit in the same section.
      claimed =
        @css
        |> String.split(~r/\n(?=\/\* =+)/)
        |> Enum.map(&without_media_blocks/1)
        |> Enum.with_index()
        |> Enum.flat_map(fn {section, index} ->
          ~r/(?:^|\n)\s*(\.[a-z][a-z0-9_-]*)\s*\{/
          |> Regex.scan(strip_comments(section))
          |> Enum.map(&{List.last(&1), index})
        end)
        |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
        |> Enum.filter(fn {_class, sections} -> Enum.uniq(sections) |> length() > 1 end)
        |> Enum.map(&elem(&1, 0))
        |> Enum.sort()

      assert claimed == [],
             "these classes are claimed by more than one section of the stylesheet, so the " <>
               "later section silently restyles the earlier one's component: " <>
               inspect(claimed)
    end
  end

  # ------------------------------------------------------------------------------------
  # Type scale (W1.8)
  # ------------------------------------------------------------------------------------

  describe "the type scale" do
    test "every section heading is the one sans face, declared in one rule" do
      # §3.1: EB Garamond display headings on `/settings`, `/status`, `/audit` and the deck
      # hero; a sans heading for the same rank on `/new`; small-caps serif card titles on
      # `/status` and `/audit` only. One rank has to be one treatment, or the rank means
      # nothing.
      declaring = rules_declaring("h2", "font-family")

      assert length(declaring) == 1,
             "#{length(declaring)} rules set a font-family for an h2; a rank with two " <>
               "faces is two ranks: #{inspect(Enum.map(declaring, &elem(&1, 0)))}"

      {selector, body} = hd(declaring)

      assert body =~ "var(--font-ui)",
             "the shared section-heading rule is not the sans face"

      for named <- [
            ".ouro-panel-head h2",
            ".ouro-panel > h2",
            ".ouro-rail-head h2",
            ".ouro-settings-section-head h2"
          ] do
        assert selector =~ named,
               "the shared section-heading rule does not cover #{named}, so that page's " <>
                 "sections keep whatever face they inherit"
      end
    end

    test "no section heading is ever the display face" do
      for {selector, body} <- rules_declaring("h2", "font-family") do
        refute body =~ "var(--font-display)", "#{selector} puts a section heading in serif"
      end

      # And the small-caps treatment goes with it: it was the `/status` and `/audit` card
      # title and nothing else wore it at this rank.
      for {selector, body} <- rules_declaring("h2", "font-variant-caps") do
        refute body =~ "small-caps", "#{selector} keeps the small-caps card title"
      end
    end

    test "every page title is the display face, on every page" do
      declaring =
        rules_declaring("h1", "font-family") ++
          rules_declaring(".ouro-new-title", "font-family")

      assert declaring != [], "nothing in app.css sets a face for a page title"

      for {selector, body} <- declaring do
        assert body =~ "var(--font-display)",
               "#{selector} draws a page title in something other than EB Garamond"
      end

      # `/new`'s title is an `h1` with a class of its own, and it is the one that was sans.
      assert Enum.any?(declaring, fn {selector, _body} -> selector =~ ".ouro-new-title" end),
             "app.css states no face for `/new`'s page title"
    end
  end

  # ------------------------------------------------------------------------------------
  # Breakpoints (W1.9)
  # ------------------------------------------------------------------------------------

  describe "the breakpoints" do
    test "every @media query is declared exactly once" do
      # §3.5: the same breakpoints were declared three times with later blocks overriding
      # earlier ones, so reading what a viewport gets meant reading the whole file in
      # order. One block per query is the only form in which that question has a local
      # answer — and it is *every* query, not only the width ones: the first version of
      # this test matched `max-width` alone and let two `prefers-reduced-motion` blocks
      # stand.
      counts =
        ~r/@media ([^{]+)\{/
        |> Regex.scan(strip_comments(@css), capture: :all_but_first)
        |> List.flatten()
        |> Enum.map(&String.trim/1)
        |> Enum.frequencies()

      repeated = Enum.filter(counts, fn {_query, count} -> count > 1 end)

      assert repeated == [],
             "these media queries are declared more than once, so what a viewport gets " <>
               "depends on which block comes last: #{inspect(repeated)}"
    end

    test "the ones the surface actually lives at are still there" do
      # A merge that lost one would pass the test above and take a whole layout with it.
      for query <- [
            "@media (max-width: 1100px)",
            "@media (max-width: 520px)",
            "@media (prefers-reduced-motion: reduce)"
          ] do
        assert @css =~ query, "#{query} is gone"
      end
    end

    test "the narrow view is where the mobile vitals disclosure is turned on" do
      # F1. `body .ouro-vitals-mobile { display: block }` outranks
      # `.ouro-vitals-mobile { display: none }` at every width, so unscoped it drew the
      # vitals twice on a desktop deck: once as the third column, once under the composer.
      block = media_block("(max-width: 1100px)")

      assert block =~ ~r/body \.ouro-vitals-mobile \{[^}]*display:\s*block/,
             "the mobile disclosure is not turned on inside the 1100px block"

      outside = String.replace(strip_comments(@css), block, "")

      refute outside =~ ~r/body \.ouro-vitals-mobile \s*\{[^}]*display:\s*block/,
             "something outside the narrow-view block turns the disclosure on at every width"
    end

    test "the narrow view neutralises `:has(> .ouro-vitals)` as well as the bare selector" do
      # W1.3 made `:has(> .ouro-vitals)` reachable for the first time, and
      # `.ouro-columns:has(> .ouro-vitals)` outranks a bare `body .ouro-columns`. Without
      # the twin, a session open on a narrow viewport keeps the two-row template the
      # stacked layout is drawn over.
      block = media_block("(max-width: 1100px)")

      assert block =~
               ~r/body \.ouro-columns,\s*body \.ouro-columns:has\(> \.ouro-vitals\)\s*\{[^}]*grid-template-rows/,
             "the narrow-view row template does not cover a grid that has a vitals column"
    end

    test "the composer's status row may wrap, so its caption is never clipped" do
      # F6, at 375px: `.ouro-auto` carries `flex: 0 0 auto` for its old home under the
      # composer, and in the status row that cut "Only for this session…" off at the
      # viewport edge.
      row = rule_for(".ouro-composer-status")
      assert row =~ "flex-wrap: wrap"

      auto = rule_for(".ouro-composer-status .ouro-auto")
      assert auto, ".ouro-composer-status .ouro-auto has no rule"
      assert auto =~ "flex-wrap: wrap"
      assert auto =~ "min-width: 0"

      assert media_block("(max-width: 520px)") =~
               ~r/\.ouro-composer-status \.ouro-auto > span \{[^}]*flex-basis:\s*100%/,
             "below 520px the caption does not get a line of its own"
    end
  end

  # ------------------------------------------------------------------------------------
  # Links
  # ------------------------------------------------------------------------------------

  describe "links" do
    test "an anchor with no class of its own is ink, not the browser's blue" do
      rule = rule_for("a")

      assert rule, "app.css states nothing about `a`; every unstyled link is browser blue"
      assert rule =~ "var(--ink)", "a plain link is not ink"
    end

    test "visited is the same ink as unvisited" do
      # Where a reader has already been is not a fact about a session. The browser's purple
      # would say it is, in a hue the token system has no name for.
      assert @css =~ ~r/a:where\(:visited\)/,
             "app.css never states a :visited colour, so the browser's purple stands"

      rule = rule_for("a,\na:where(:visited)") || rule_for("a")
      assert rule =~ "var(--ink)"
    end

    test "no link state is ever the attention green" do
      # Rule 1 of the stylesheet's own header: the green means "a human is needed here".
      # A link is a way to somewhere, which is not that.
      for selector <- [
            "a",
            "a:where(:hover)",
            ".ouro-new-back",
            ".ouro-prose a"
          ] do
        rule = rule_for(selector)
        assert rule, "#{selector} has no rule in app.css"
        refute rule =~ "attention-green", "#{selector} spends the attention green"
      end
    end

    test "hover moves to secondary, and the component rules still outrank it" do
      # `:where()` is load-bearing. `a:visited` at its natural specificity would outrank
      # every single-class rule below it and light a settled rail row back up to full ink.
      assert @css =~ ~r/a:where\(:hover\)/,
             "the global hover rule is not wrapped in :where(); it will outrank " <>
               ".ouro-row-settled and .ouro-new-back"

      assert rule_for("a:where(:hover)") =~ "var(--secondary)"
    end
  end

  # ------------------------------------------------------------------------------------
  # Focus
  # ------------------------------------------------------------------------------------

  describe "focus" do
    test "there is one global focus ring" do
      rule = rule_for(":focus-visible")

      assert rule, "app.css has no global focus treatment"
      assert rule =~ "outline:", "the global focus rule draws no outline"
      assert rule =~ "var(--", "the focus ring is not a token colour"
    end

    test "nothing removes a focus ring" do
      # A keyboard is a first-class way to drive an operator surface. `outline: none` and
      # `outline: 0` are how that stops being true. Comments are stripped first: this file's
      # own prose says the words, and a test that failed on its own explanation would be a
      # test nobody could write the explanation for.
      refute strip_comments(@css) =~ ~r/outline:\s*(none|0)\s*;/,
             "app.css removes a focus outline somewhere; every focus must stay visible"
    end
  end

  # ------------------------------------------------------------------------------------
  # Themes
  # ------------------------------------------------------------------------------------

  describe "the two themes" do
    test "every colour in the file is a token" do
      # A literal colour outside the token blocks is a colour the light theme cannot reach,
      # which is how a palette ends up half-translated.
      literals =
        @css
        |> strip_comments()
        |> strip_token_blocks()
        |> then(&Regex.scan(~r/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/, &1))
        |> List.flatten()

      assert literals == [],
             "app.css sets colours outside the token blocks: #{inspect(literals)}"
    end

    test "every colour token declared for dark is declared for light" do
      dark = colour_tokens(":root")
      light = colour_tokens(~s([data-theme="light"]))

      missing = MapSet.difference(MapSet.new(Map.keys(dark)), MapSet.new(Map.keys(light)))

      assert MapSet.size(missing) == 0,
             "these colour tokens have no light value, so the light theme inherits the " <>
               "dark one: #{inspect(Enum.sort(missing))}"
    end

    test "the light theme actually inverts, rather than restating the dark values" do
      dark = colour_tokens(":root")
      light = colour_tokens(~s([data-theme="light"]))

      unchanged =
        dark
        |> Enum.filter(fn {name, value} -> Map.get(light, name) == value end)
        |> Enum.map(&elem(&1, 0))

      assert unchanged == [],
             "these tokens carry the same value in both themes: #{inspect(unchanged)}"
    end

    test "the page and the ink swap sides between the themes" do
      dark = colour_tokens(":root")
      light = colour_tokens(~s([data-theme="light"]))

      assert luminance(dark["--page"]) < luminance(dark["--ink"]),
             "the dark theme does not have light ink on a dark page"

      assert luminance(light["--page"]) > luminance(light["--ink"]),
             "the light theme does not have dark ink on a light page"
    end

    test "each theme's layers stack, and both stack the same way" do
      # Rule 2: layers separate by hairline, not by shadow, so the *order* is what tells a
      # reader which surface is in front. A palette whose layers were not monotonic would
      # read as noise rather than as depth.
      #
      # Both themes go *lighter* forwards, which is the one thing about this palette that
      # is not an inversion: the page recedes to a grey in light and to near-black in dark,
      # and in both a card is the brightest thing on it. Asserted rather than assumed —
      # the first version of this test assumed light would mirror dark and was wrong.
      layers = ["--page", "--workspace", "--panel", "--card"]

      for selector <- [":root", ~s([data-theme="light"])] do
        values = colour_tokens(selector)
        steps = Enum.map(layers, &luminance(values[&1]))

        assert steps == Enum.sort(steps),
               "#{selector} layers do not stack: #{inspect(Enum.zip(layers, steps))}"
      end
    end

    test "the light theme keeps ink legible on every layer it is drawn on" do
      # 4.5:1 is the WCAG AA floor for body text. Asserted for light because light is the
      # theme nothing had ever rendered before this slice — the dark palette shipped in W0
      # and has been looked at since.
      light = colour_tokens(~s([data-theme="light"]))

      for layer <- ["--page", "--workspace", "--panel", "--card", "--inset"] do
        ratio = contrast(light["--ink"], light[layer])

        assert ratio >= 4.5,
               "light --ink on #{layer} is #{Float.round(ratio, 2)}:1, below the 4.5:1 floor"
      end
    end

    test "semantic tones meet the body-text contrast floor in both themes" do
      for selector <- [":root", ~s([data-theme="light"])] do
        values = colour_tokens(selector)

        for token <- ["--attention-green", "--warn-amber", "--danger", "--secondary"] do
          ratio = contrast(values[token], values["--card"])

          assert ratio >= 4.5,
                 "#{selector} #{token} on --card is #{Float.round(ratio, 2)}:1, " <>
                   "below the 4.5:1 floor"
        end
      end
    end

    test "the light diff washes read as emphasis rather than as a verdict" do
      light = colour_tokens(~s([data-theme="light"]))

      for {bg, ink} <- [
            {"--diff-add-bg", "--diff-add-ink"},
            {"--diff-remove-bg", "--diff-remove-ink"}
          ] do
        ratio = contrast(light[ink], light[bg])
        assert ratio >= 4.5, "light #{ink} on #{bg} is #{Float.round(ratio, 2)}:1"
      end

      # And neither of them is the attention green or the danger red, in either theme.
      for selector <- [":root", ~s([data-theme="light"])] do
        values = colour_tokens(selector)

        refute values["--diff-add-ink"] == values["--attention-green"]
        refute values["--diff-remove-ink"] == values["--danger"]
      end
    end
  end

  # ------------------------------------------------------------------------------------
  # The chrome controls
  # ------------------------------------------------------------------------------------

  describe "the chrome toggles" do
    test "the icon buttons are furniture, not the page's action" do
      rule = rule_for(".ouro-icon-button")

      assert rule, ".ouro-icon-button has no rule in app.css"
      refute rule =~ "attention-green", "the chrome toggles spend the attention green"
      refute rule =~ "button-bg", "the chrome toggles wear the filled-button accent"
    end

    test "the pressed state is ink, and the bell in particular is never green" do
      pressed = rule_for(~s(.ouro-icon-button[aria-pressed="true"]))

      assert pressed, "the pressed state has no rule"
      assert pressed =~ "var(--ink)"
      refute pressed =~ "attention-green"
    end
  end

  # ------------------------------------------------------------------------------------
  # Helpers
  # ------------------------------------------------------------------------------------

  defp rule_for(selector) do
    case Regex.run(~r/(?<![-\w])#{Regex.escape(selector)}\s*\{([^}]*)\}/, @css) do
      [_whole, body] -> body
      nil -> nil
    end
  end

  defp strip_comments(css), do: Regex.replace(~r|/\*.*?\*/|s, css, "")

  # Every rule whose selector list mentions `needle` and whose body declares `property`,
  # as `{selector, body}`.
  defp rules_declaring(needle, property) do
    ~r/([^{}]+)\{([^{}]*)\}/
    |> Regex.scan(strip_comments(@css), capture: :all_but_first)
    |> Enum.map(fn [selector, body] -> {String.trim(selector), body} end)
    |> Enum.filter(fn {selector, body} ->
      mentions?(selector, needle) and body =~ ~r/(?:^|;)\s*#{Regex.escape(property)}\s*:/
    end)
  end

  # `h2` must be a whole token, or `h2` would match nothing and `.ouro-new-title` would
  # also match `.ouro-new-title-x`.
  defp mentions?(selector, needle),
    do: selector =~ ~r/(?<![\w-])#{Regex.escape(needle)}(?![\w-])/

  # One top-level `@media` block, by its query, comments stripped.
  defp media_block(query) do
    strip_comments(@css)
    |> media_block_bodies()
    |> Enum.find(&String.starts_with?(&1, "@media " <> query <> " {"))
    |> case do
      nil -> flunk("app.css has no @media #{query} block")
      block -> block
    end
  end

  # Everything except the top-level `@media` blocks.
  defp without_media_blocks(css),
    do: Enum.reduce(media_block_bodies(css), css, &String.replace(&2, &1, "", global: false))

  defp media_block_bodies(css) do
    css
    |> String.split("\n@media ")
    |> Enum.drop(1)
    |> Enum.map(&close_at_depth_zero("@media " <> &1))
  end

  # One `@media` block, from its `@media` up to the `}` that closes it.
  defp close_at_depth_zero(text) do
    text
    |> String.graphemes()
    |> Enum.reduce_while({[], 0, false}, fn
      "{", {taken, depth, _opened} -> {:cont, {["{" | taken], depth + 1, true}}
      "}", {taken, 1, true} -> {:halt, {["}" | taken], 0, true}}
      "}", {taken, depth, opened} -> {:cont, {["}" | taken], depth - 1, opened}}
      char, {taken, depth, opened} -> {:cont, {[char | taken], depth, opened}}
    end)
    |> elem(0)
    |> Enum.reverse()
    |> Enum.join()
  end

  # The two `:root` blocks and the two `[data-theme="light"]` blocks are where literal
  # colours are supposed to be.
  defp strip_token_blocks(css) do
    Regex.replace(~r/(?:^|\n)(?::root|\[data-theme="light"\])\s*\{[^}]*\}/, css, "")
  end

  # Every colour token a selector declares, across all of its blocks — the palette is split
  # into two `:root` blocks on purpose (the base, then the deck's diff washes).
  defp colour_tokens(selector) do
    ~r/(?<![-\w])#{Regex.escape(selector)}\s*\{([^}]*)\}/
    |> Regex.scan(strip_comments(@css))
    |> Enum.flat_map(fn [_whole, body] ->
      ~r/(--[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;/
      |> Regex.scan(body)
      |> Enum.map(fn [_all, name, value] -> {name, String.downcase(value)} end)
    end)
    |> Map.new()
  end

  # WCAG relative luminance and contrast, written out rather than pulled in: they are eight
  # lines and a dependency for eight lines is a dependency to keep green.
  defp luminance("#" <> hex) do
    [r, g, b] =
      hex
      |> String.to_charlist()
      |> Enum.chunk_every(2)
      |> Enum.map(fn pair -> pair |> List.to_string() |> String.to_integer(16) end)
      |> Enum.map(&channel/1)

    0.2126 * r + 0.7152 * g + 0.0722 * b
  end

  defp channel(value) do
    ratio = value / 255
    if ratio <= 0.03928, do: ratio / 12.92, else: :math.pow((ratio + 0.055) / 1.055, 2.4)
  end

  defp contrast(one, two) do
    [dim, bright] = Enum.sort([luminance(one), luminance(two)])
    (bright + 0.05) / (dim + 0.05)
  end
end
