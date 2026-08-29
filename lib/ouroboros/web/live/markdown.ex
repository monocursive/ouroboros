defmodule Ouroboros.Web.Live.Markdown do
  @moduledoc """
  Agent prose as HTML, built from an allowlist rather than filtered against a blocklist.

  ## The threat, stated plainly

  An agent message is **untrusted input**. Its text comes from a model that read a
  repository, a web page, a tool's output, and a stranger's issue tracker, and any of
  those can contain markup written to be executed in the operator's browser. That browser
  holds the session cookie for a surface that can start agents. So the question this
  module answers is not "does Markdown look right" — it is "what is the complete set of
  things this renderer can emit".

  ## Why an allowlist and not `escape: true` alone

  Because `escape: true` covers less than its name suggests, and this was **measured, not
  assumed** (`test/ouroboros/web/live/markdown_test.exs`):

    * *Inline* raw HTML is escaped. `Hello <script>x</script>` inside a paragraph arrives
      in the AST as text, and renders as characters.
    * *Block-level* raw HTML is **not**. `<script>alert(1)</script>` on a line of its own
      is parsed into a real AST node — tag, attributes and all — and a renderer that
      walked the AST trusting the option would emit it.
    * Markdown's own link syntax is untouched either way:
      `[click](javascript:alert(1))` parses to an anchor whose `href` Earmark passes
      straight through.

  So the option is set, and then the AST is rendered against an allowlist that does not
  depend on it. `@tags` is every element this module can produce and `attribute/2` is
  every attribute, per element; anything else is dropped and its children rendered in
  place, so unknown structure loses its markup and keeps its words. A URL is admitted only
  by its scheme (`@schemes`), and a scheme-relative `//host` is refused with them because
  it inherits the page's.

  ## What it costs

  Tables, images from remote hosts, inline HTML an author meant, and anchors' `id`s all
  render as less than they were written as. That is the deal: the rendering is bounded by
  a list a reader of this file can hold in their head, and no future Earmark option
  changes what reaches the page.
  """

  # Every element this renderer can emit. Read as: nothing else can appear in a message.
  @tags ~w(
    p br hr
    em strong del code pre blockquote
    ul ol li
    h1 h2 h3 h4 h5 h6
    a
    table thead tbody tr th td
  )

  # Void elements, which must not be given a closing tag.
  @void ~w(br hr)

  # `mailto` earns its place because agents cite addresses; `data:` and `javascript:` are
  # absent on purpose, and so is `//host`, which inherits whatever scheme served the page.
  @schemes ~w(http https mailto)

  # A code fence's info string reaches the AST as a class, so it is attacker-controlled
  # text on an attribute. Bounded to a shape that cannot escape the attribute or name a
  # class this stylesheet gives meaning to.
  @class_shape ~r/\A[a-zA-Z0-9_-]{1,32}\z/

  @doc """
  One agent message as safe HTML.

  Returns a `{:safe, iodata}` tuple, so a template interpolates it without escaping it
  again — which is the whole reason the escaping in here has to be right.
  """
  @spec to_html(String.t() | nil) :: {:safe, iodata()}
  def to_html(nil), do: {:safe, []}

  def to_html(text) when is_binary(text) do
    # Earmark returns `{:error, ast, messages}` for a document it had complaints about and
    # still gives the AST, which is the one it built from what it could read. A message
    # with an unclosed fence is still a message a person needs to see.
    ast =
      case Earmark.Parser.as_ast(text, earmark_options()) do
        {:ok, ast, _messages} -> ast
        {:error, ast, _messages} -> ast
      end

    {:safe, Enum.map(ast, &node_to_iodata/1)}
  end

  @doc """
  The parser options, named so a test can assert the two that are load-bearing.

  `escape: true` is Earmark's default and is written out anyway: a default is a thing that
  can change in a minor release, and this one is a security property.
  """
  @spec earmark_options() :: keyword()
  def earmark_options do
    [
      escape: true,
      # Typographic quotes in a transcript would silently rewrite a command an operator is
      # about to copy. Off.
      smartypants: false,
      breaks: false,
      # Earmark can be handed functions that run over the AST. Nothing here hands it any,
      # and saying so is cheaper than trusting that nothing ever will.
      registered_processors: []
    ]
  end

  @doc """
  Whether a URL may be linked to.

  Public because it is the property most worth testing directly and the one a reader of a
  test file should be able to see enumerated.
  """
  @spec safe_url?(term()) :: boolean()
  def safe_url?(url) when is_binary(url) do
    trimmed = url |> String.trim() |> strip_controls()

    cond do
      trimmed == "" ->
        false

      # Protocol-relative: no scheme of its own, so it borrows the page's and reaches an
      # arbitrary host. Refused with the schemes it is pretending not to have.
      String.starts_with?(trimmed, "//") ->
        false

      # In-document and same-origin references carry no scheme and reach nowhere new.
      String.starts_with?(trimmed, "#") or String.starts_with?(trimmed, "/") ->
        true

      true ->
        case URI.new(trimmed) do
          {:ok, %URI{scheme: nil}} -> not String.contains?(trimmed, ":")
          {:ok, %URI{scheme: scheme}} -> String.downcase(scheme, :ascii) in @schemes
          {:error, _part} -> false
        end
    end
  end

  def safe_url?(_url), do: false

  # ------------------------------------------------------------------------------------

  defp node_to_iodata(text) when is_binary(text), do: escape(text)

  defp node_to_iodata({tag, attributes, children, _meta}) when is_binary(tag) do
    tag = String.downcase(tag, :ascii)

    cond do
      tag not in @tags ->
        # Dropped, not deleted: the words survive, the markup does not. A message whose
        # renderer swallowed a paragraph because of one unknown wrapper would be the
        # failure this whole module exists to avoid.
        Enum.map(children, &node_to_iodata/1)

      tag in @void ->
        ["<", tag, attributes_to_iodata(tag, attributes), " />"]

      true ->
        [
          "<",
          tag,
          attributes_to_iodata(tag, attributes),
          ">",
          Enum.map(children, &node_to_iodata/1),
          "</",
          tag,
          ">"
        ]
    end
  end

  # An AST node this build does not recognize. It is not rendered, because a renderer that
  # guessed at a shape it does not know is a renderer that can be surprised into emitting
  # something.
  defp node_to_iodata(_other), do: []

  defp attributes_to_iodata(tag, attributes) when is_list(attributes) do
    attributes
    |> Enum.flat_map(&attribute(tag, &1))
    |> Enum.map(fn {name, value} -> [" ", name, ~s(="), escape(value), ~s(")] end)
  end

  defp attributes_to_iodata(_tag, _attributes), do: []

  # An anchor: the href if its scheme is one of three, and the two rel tokens that stop a
  # link in untrusted prose from reaching back into this tab.
  defp attribute("a", {"href", value}) do
    if safe_url?(value) do
      [
        {"href", value |> String.trim() |> strip_controls()},
        {"rel", "nofollow noopener noreferrer"},
        {"target", "_blank"}
      ]
    else
      []
    end
  end

  defp attribute(tag, {"class", value}) when tag in ["code", "pre"] do
    if is_binary(value) and Regex.match?(@class_shape, value),
      do: [{"class", "ouro-md-lang-" <> value}],
      else: []
  end

  defp attribute(tag, {"title", value}) when tag in ["a", "code", "pre"] and is_binary(value),
    do: [{"title", value}]

  defp attribute(_tag, _attribute), do: []

  # C0 controls and the separators a URL parser and a browser can disagree about. Stripped
  # before the scheme check *and* carried into the emitted value, so the string that was
  # judged safe is the string that is written.
  defp strip_controls(value) do
    String.replace(value, ~r/[\x00-\x20\x7f\x{2028}\x{2029}]/u, "")
  end

  defp escape(value) when is_binary(value) do
    value
    |> Phoenix.HTML.html_escape()
    |> Phoenix.HTML.safe_to_string()
  end

  defp escape(value), do: escape(to_string(value))
end
