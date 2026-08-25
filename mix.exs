defmodule Ouroboros.MixProject do
  use Mix.Project

  def project do
    [
      app: :ouroboros,
      version: "0.1.0",
      elixir: "~> 1.20",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      # Gradual success typing. PLTs live under `_build/plts` (already gitignored with
      # `_build/`) so they are not dumped in the repo root. `:error_handling` only:
      # `:underspecs` / `:overspecs` / `:unmatched_returns` wait until this baseline is
      # honest rather than drowning the first run. Existing warnings live in
      # `dialyzer.ignore-warnings`; new files and new warning types must still be clean.
      dialyzer: [
        plt_local_path: "_build/plts",
        flags: [:error_handling],
        ignore_warnings: "dialyzer.ignore-warnings"
      ],
      releases: releases()
    ]
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
      # `:inets`/`:ssl` are the native agent's `web_fetch`: `:httpc` is OTP's own client,
      # it takes `autoredirect: false`, and it adds no dependency to a runtime that
      # otherwise makes no outbound HTTP request of its own.
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
      # Cluster formation. The runtime's distribution semantics never depended on how
      # nodes found each other; this is the discovery half, and it stays off unless
      # `OUROBOROS_CLUSTER_STRATEGY` names a strategy.
      {:libcluster, "~> 3.5"},
      # Jido.Harness 2.0 is not on Hex yet. Pin the reviewed upstream commit so
      # provider protocol changes cannot enter the runtime implicitly.
      {:jido_harness,
       github: "agentjido/jido_harness", ref: "8bf0d52f4fed0d8a9d2594000d8b3a775da16f8b"},
      # Gradual success typing (`mix dialyzer` / `make dialyzer`, and a CI job). Runtime
      # false so a packaged node never ships the checker; `:dev`/`:test` so the lock
      # still pins it for CI.
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]
end
