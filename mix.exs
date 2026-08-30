defmodule Ouroboros.MixProject do
  use Mix.Project

  def project do
    [
      app: :ouroboros,
      version: "0.1.0",
      elixir: "~> 1.20",
      elixirc_paths: elixirc_paths(Mix.env()),
      compilers: Mix.compilers() ++ [:ouroboros_fs_filter],
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      # Gradual success typing. PLTs live under `_build/plts` (already gitignored with
      # `_build/`) so they are not dumped in the repo root. `:error_handling` only:
      # `:underspecs` / `:overspecs` / `:unmatched_returns` wait until this baseline is
      # honest rather than drowning the first run. Existing warnings live in
      # `dialyzer.ignore-warnings`; new files and new warning types must still be clean.
      dialyzer: [
        plt_local_path: "_build/plts",
        # Three apps this code calls that dialyxir does not put in the PLT on its own, so
        # every call into them read as `Unknown function` and hid whatever was really
        # there. `:mix` is the Mix tasks under `lib/mix/tasks` and `Mix.env/0`;
        # `:ex_unit` is the Forge sandbox, which runs a suite in-process
        # (`ExUnit.start/1`, `ExUnit.run/0`); `:llm_db` is an `included_applications` of
        # `req_llm`, which is why it is absent by default — `req_llm` adds it to its own
        # PLT for the same reason.
        plt_add_apps: [:mix, :ex_unit, :llm_db],
        flags: [:error_handling],
        ignore_warnings: "dialyzer.ignore-warnings"
      ],
      aliases: aliases(),
      releases: releases()
    ]
  end

  # `web.assets` hangs off `compile` rather than off a build step of its own because the
  # two consumers that must never miss it are `mix compile` in a development loop and
  # `mix release`, which compiles on its way to `:assemble`. One hook covers both, and a
  # release then picks up `priv/static/web/` with the same verbatim `priv/` copy it has
  # always done — no new packaging mechanism, and still no Node.
  defp aliases do
    [
      "web.assets": &copy_web_assets/1,
      compile: ["web.assets", "compile"]
    ]
  end

  # The JavaScript `Ouroboros.Web` serves is the prebuilt bundle that already shipped
  # inside each dependency. It is copied, never built: this repo has no JavaScript
  # toolchain, and the alternative to a copy is esbuild, a package.json, and a second
  # toolchain to keep green for two files nobody edits.
  #
  # They are copied rather than committed because a vendored copy of a dependency's asset
  # is a file that silently disagrees with the dependency after the next `mix deps.get`.
  @web_assets [
    {"deps/phoenix/priv/static/phoenix.min.js", "priv/static/web/phoenix.min.js"},
    {"deps/phoenix_live_view/priv/static/phoenix_live_view.min.js",
     "priv/static/web/phoenix_live_view.min.js"}
  ]

  defp copy_web_assets(_args) do
    Enum.each(@web_assets, fn {source, destination} ->
      cond do
        not File.regular?(source) ->
          # Reachable only before `mix deps.get`, where every other task fails too. Say
          # which file is missing rather than letting the browser find out.
          Mix.raise("web.assets: #{source} is missing; run `mix deps.get` first")

        stale?(source, destination) ->
          File.mkdir_p!(Path.dirname(destination))
          File.cp!(source, destination)

        true ->
          :ok
      end
    end)
  end

  defp stale?(source, destination) do
    case {File.stat(source, time: :posix), File.stat(destination, time: :posix)} do
      {{:ok, from}, {:ok, to}} -> from.mtime > to.mtime or from.size != to.size
      _missing -> true
    end
  end

  # One artifact for every node role. A `:builder` and a `:core` node must run the same
  # ERTS, Elixir, and architecture or the verifier rejects what the builder produced on
  # every target, so they are the same release booted with a different
  # `OUROBOROS_NODE_ROLE` rather than separate builds. `rel/env.sh.eex` and
  # `rel/vm.args.eex` carry the distribution posture; see the README's "Running a
  # cluster".
  defp releases do
    [
      ouroboros: [
        include_executables_for: [:unix],
        # The tarball is not an extra artifact beside the assembled tree, it is the one
        # both consumers take: a server deploy unpacks it, and `ouro` bakes it into the
        # client binary. Assembling without it would leave the packaging step to a
        # hand-written `tar` invocation whose contents nobody checks.
        steps: [:assemble, :tar],
        applications: [ouroboros: :permanent, runtime_tools: :permanent]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: {Ouroboros.Application, []},
      # `:ssl` is the native agent's `web_fetch` (Mint). `:inets` stays for any
      # remaining OTP HTTP callers.
      extra_applications: [:logger, :crypto, :sasl, :inets, :ssl]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jido, "~> 2.3"},
      {:jido_ai, "~> 2.3"},
      # Ouroboros calls ReqLLM directly from the in-process provider. Keep that boundary
      # explicit rather than relying on Jido.AI's transitive dependency.
      {:req_llm, "~> 1.20"},
      # `ouroboros.toml` — the native agent's hooks and `[checks]` — is TOML because
      # every other agent's project configuration is. The library is already in the tree
      # as `llm_db`'s dependency; it is declared here so the runtime reads a dependency
      # it named rather than one it inherited.
      {:toml, "~> 0.7"},
      # `web_fetch` streams every status through Mint so a 302/404 body is cancelled at
      # the cap the way a 200 already was. Declared here rather than inherited from Req
      # so the runtime names the client it opens sockets with.
      {:mint, "~> 1.8"},
      # Cluster formation. The runtime's distribution semantics never depended on how
      # nodes found each other; this is the discovery half, and it stays off unless
      # `OUROBOROS_CLUSTER_STRATEGY` names a strategy.
      {:libcluster, "~> 3.5"},
      # `Ouroboros.Web` — the LiveView operator surface (docs/WEB.md). Four packages and
      # nothing else: there is no Node, no esbuild, no Tailwind, and no asset pipeline in
      # this repo, and adding one to serve a handful of hand-written files would be a
      # second toolchain to keep green for zero user-visible gain. The JavaScript these
      # deps already ship prebuilt is copied into `priv/static/web/` by the `web.assets`
      # alias below; the CSS is hand-authored.
      #
      # `phoenix_pubsub` arrives transitively and is already optional-compatible with
      # `jido_signal`, so it needs no declaration of its own.
      {:phoenix, "~> 1.8"},
      {:phoenix_live_view, "~> 1.2"},
      {:phoenix_html, "~> 4.3"},
      # Bandit rather than Cowboy: it is pure Elixir, so the web surface adds nothing to
      # the release's native build graph, which the Rust dist triples already pay for.
      {:bandit, "~> 1.12"},
      # Markdown for agent messages. Pure Elixir on purpose: MDEx renders faster but is a
      # Rust NIF, which would entangle the two dist triples for no user-visible gain at
      # these payload sizes (docs/WEB.md §3). Agent output is untrusted, so it is rendered
      # with `escape: true` and never with raw HTML passed through — see
      # `Ouroboros.Web.Live.Markdown`.
      {:earmark, "~> 1.4"},
      # Jido.Harness 2.0 is not on Hex yet. Pin the reviewed upstream commit so
      # provider protocol changes cannot enter the runtime implicitly.
      {:jido_harness,
       github: "agentjido/jido_harness", ref: "8bf0d52f4fed0d8a9d2594000d8b3a775da16f8b"},
      # Gradual success typing (`mix dialyzer` / `make dialyzer`, and a CI job). Runtime
      # false so a packaged node never ships the checker; `:dev`/`:test` so the lock
      # still pins it for CI.
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      # `Phoenix.LiveViewTest` refuses to mount a view without this and says so by name
      # (`phoenix_live_view/test/dom.ex:15`). It is the HTML parser the test helpers walk
      # the rendered page with, it is `only: :test`, and without it the web surface has no
      # headless test story at all — which was the argument for the surface.
      {:lazy_html, ">= 0.1.0", only: :test}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]
end
