defmodule Ouroboros.Web.Live.MarkdownTest do
  @moduledoc """
  What an agent message can and cannot put in an operator's browser.

  This is the one file in the slice where a passing test is a security property rather
  than a rendering preference. The browser reading this page holds the session cookie for
  a surface that can start agents; the text being rendered came from a model that read a
  repository, a web page, a tool's output and a stranger's issue tracker. Every `refute`
  below is a thing that must never reach the DOM.

  The positive tests exist for a reason too: a sanitizer that broke ordinary prose would
  be replaced by one that did not, so what survives is asserted as carefully as what does
  not.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Web.Live.Markdown

  defp html(text), do: text |> Markdown.to_html() |> Phoenix.HTML.safe_to_string()

  describe "raw HTML in a message" do
    test "a script tag is characters, not a tag" do
      out = html("Here is the fix: <script>fetch('/artifact')</script> done")

      refute out =~ "<script"
      assert out =~ "&lt;script&gt;"
      # And the words are still readable, which is the point of escaping rather than
      # stripping: a message that mentioned a script tag still says so.
      assert out =~ "fetch"
    end

    test "an event handler on an invented tag cannot ride in" do
      out = html("<div onload=\"alert(1)\">hello</div>")

      refute out =~ "onload"
      refute out =~ "<div"
      assert out =~ "hello"
    end

    test "an iframe is nothing at all" do
      out = html("<iframe src=\"https://evil.example\"></iframe>")

      refute out =~ "<iframe"
      refute out =~ "evil.example"
    end

    test "an img with an onerror handler never becomes an element" do
      out = html("<img src=x onerror=\"alert(1)\">")

      refute out =~ "<img"
      refute out =~ "onerror=\""
    end

    test "a style block cannot restyle the deck" do
      out = html("<style>.ouro-deck { display: none }</style>")

      # The tag is dropped and its body survives as visible text, which is the allowlist's
      # rule for an unknown element: lose the markup, keep the words.
      refute out =~ "<style"
      assert out =~ ".ouro-deck { display: none }"
    end
  end

  # These matter more than the inline cases above, and are separated out because they
  # falsify the obvious assumption about why the inline ones pass.
  #
  # `escape: true` does **not** escape block-level HTML: Earmark parses it into real AST
  # nodes, tags and attributes and all. `<script>alert(1)</script>` on a line of its own
  # arrives as a `script` node, not as the characters `&lt;script&gt;`. What stops it is
  # the tag allowlist, and nothing else — which is why this module builds HTML from an
  # allowlist rather than trusting the parser's escaping.
  describe "block-level raw HTML, where the allowlist is the only thing standing" do
    test "a script block on its own line becomes inert text" do
      out = html("<script>alert(document.cookie)</script>")

      refute out =~ "<script"
      # The body survives as text, which is inert, and says what was attempted.
      assert out =~ "alert(document.cookie)"
    end

    test "an anchor written as raw HTML gets its href checked like any other" do
      out = html("<a href=\"javascript:alert(1)\">click</a>")

      refute out =~ "javascript:"
      refute out =~ "<a "
      assert out =~ "click"
    end

    test "an allowlisted tag carrying an event handler keeps the tag and loses the handler" do
      out = html("<p onclick=\"alert(1)\">hello</p>")

      assert out =~ "<p>hello</p>"
      refute out =~ "onclick"
    end

    test "an svg payload does not survive" do
      out = html("<svg><script>alert(1)</script></svg>")

      refute out =~ "<svg"
      refute out =~ "<script"
    end
  end

  describe "link hrefs" do
    test "a javascript: link renders inert" do
      out = html("[click me](javascript:alert(document.cookie))")

      refute out =~ "javascript:"
      refute out =~ "<a "
      # The words survive; only the link does not.
      assert out =~ "click me"
    end

    test "a data: link renders inert" do
      out = html("[open](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)")

      refute out =~ "<a "
      refute out =~ "data:text/html"
    end

    test "a scheme obscured by control characters is still refused" do
      # `java\tscript:` and friends: browsers strip the control character and follow the
      # scheme, so a check that ran before stripping would pass the wrong string.
      out = html("[x](java\tscript:alert(1))")

      refute out =~ "<a "
    end

    test "a protocol-relative link is refused with the schemes it is pretending not to have" do
      out = html("[x](//evil.example/steal)")

      refute out =~ "<a "
    end

    test "http and https links are kept, and cannot reach back into this tab" do
      out = html("[docs](https://example.com/a)")

      assert out =~ ~s(href="https://example.com/a")
      assert out =~ "noopener"
      assert out =~ "noreferrer"
      assert out =~ "nofollow"
      assert out =~ ~s(target="_blank")
    end

    test "mailto survives, because agents cite addresses" do
      assert html("[write](mailto:someone@example.com)") =~ ~s(href="mailto:someone@example.com")
    end

    test "the allowlist is enumerated, not guessed at" do
      for url <- ["https://a.example", "http://a.example", "mailto:a@b.c", "#anchor", "/local"] do
        assert Markdown.safe_url?(url), "#{url} should be linkable"
      end

      for url <- [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html,<script>",
            "vbscript:x",
            "file:///etc/passwd",
            "//evil.example",
            "",
            "   "
          ] do
        refute Markdown.safe_url?(url), "#{url} should not be linkable"
      end
    end
  end

  describe "ordinary prose" do
    test "renders as the document it is" do
      out =
        html("""
        # Heading

        A paragraph with **bold**, *italic* and `code`.

        - one
        - two

        > quoted

        ```elixir
        IO.puts("hi")
        ```
        """)

      assert out =~ "<h1>Heading</h1>"
      assert out =~ "<strong>bold</strong>"
      assert out =~ "<em>italic</em>"
      assert out =~ "<code"
      assert out =~ "<li>"
      assert out =~ "<blockquote>"
      assert out =~ "<pre>"
      assert out =~ "IO.puts"
    end

    test "a fence's language becomes a namespaced class and never raw attribute text" do
      assert html("```elixir\nx\n```") =~ ~s(class="ouro-md-lang-elixir")

      # Namespaced, so a fence cannot name one of this stylesheet's own classes and
      # restyle the deck from inside a message.
      assert html("```ouro-deck\nx\n```") =~ ~s(class="ouro-md-lang-ouro-deck")
      refute html("```ouro-deck\nx\n```") =~ ~s(class="ouro-deck")

      # A fence info string is attacker-controlled text. Whatever it is, it never becomes
      # an attribute: the shape check refuses anything that is not a plain word, and the
      # escaping means the characters land as content if they land at all.
      out = html("```a\" onmouseover=\"alert(1)\nx\n```")
      refute out =~ ~s(onmouseover=")
    end

    test "code content is escaped inside the block" do
      out = html("```\n<script>alert(1)</script>\n```")

      refute out =~ "<script>"
      assert out =~ "&lt;script&gt;"
    end

    test "a table renders, with the styles Earmark wanted dropped" do
      out = html("| a | b |\n|---|---|\n| 1 | 2 |")

      assert out =~ "<table>"
      assert out =~ "<td>1</td>"
      refute out =~ "style="
    end

    test "smart quotes are off, so a command survives being copied out of a transcript" do
      out = html("Run \"make web\" -- it works")

      assert out =~ ~s(&quot;make web&quot;)
      refute out =~ "&#8220;"
    end

    test "nothing at all is nothing at all" do
      assert html("") == ""
      assert Markdown.to_html(nil) == {:safe, []}
    end

    test "an unclosed fence still renders the words it had" do
      # Earmark reports this as an error and hands back the AST it built. A message with a
      # broken fence is still a message a person needs to read.
      assert html("```elixir\nIO.puts(1)") =~ "IO.puts(1)"
    end
  end

  describe "the parser options" do
    test "name escaping explicitly rather than relying on a default that could move" do
      options = Markdown.earmark_options()

      assert options[:escape] == true
      assert options[:smartypants] == false
      assert options[:registered_processors] == []
    end
  end
end
