# Used by "mix format"
[
  # `Ouroboros.Web`'s endpoint and router are written in Phoenix's macro dialect, where
  # `plug`, `socket`, `scope`, and `live` read as declarations rather than as calls. The
  # deps export that list; importing it is what keeps the formatter from parenthesising
  # them back into function calls. It removes no parentheses from anything already
  # written with them, so no file outside `lib/ouroboros/web/` changes shape.
  import_deps: [:phoenix, :phoenix_live_view],
  # `~H` sigils are HTML, and the plugin is the only thing that formats them as HTML.
  plugins: [Phoenix.LiveView.HTMLFormatter],
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"]
]
