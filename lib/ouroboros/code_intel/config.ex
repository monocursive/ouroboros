defmodule Ouroboros.CodeIntel.Config do
  @moduledoc """
  Reads the `:code_intel` application environment and answers with defaults.

  Every value this returns is a bound: a timeout, a cap, a byte budget, or a retention
  window. There is no `:infinity` here and none is accepted — a non-positive or
  non-integer setting falls back to the shipped default rather than disabling the bound,
  because a mistyped operator value must never widen what a language server may consume.
  """

  @defaults [
    # Lazy spawn means nothing runs until a caller asks; this switch exists so an
    # operator can refuse language servers on a host outright.
    enabled: true,
    # Hermes' documented idle timeout, and the only reason a healthy server ever stops.
    idle_ms: 600_000,
    # How often the pool checks for idle servers and stale broken marks.
    sweep_ms: 5_000,
    # OpenCode's and Kilo's numbers: ordinary requests are cheap, `initialize` is not
    # (ElixirLS and jdtls compile or index the world on first launch).
    request_timeout_ms: 10_000,
    initialize_timeout_ms: 45_000,
    # `shutdown`/`exit` are a courtesy; after this the OS process is killed.
    shutdown_grace_ms: 5_000,
    max_restarts: 3,
    restart_backoff_ms: 1_000,
    # Once a key is broken, every call answers `{:error, :broken}` for this long rather
    # than respawning a server that has already failed on every edit.
    broken_ms: 3_600_000,
    # Per host, then per server. Serena's 30 GB incidents and Anthropic's advice to
    # disable plugins under memory pressure are why these exist at all.
    memory_budget_bytes: 4 * 1024 * 1024 * 1024,
    server_memory_limit_bytes: 2 * 1024 * 1024 * 1024,
    memory_poll_ms: 30_000,
    # OpenCode's published debounce and document-diagnostics wait.
    diagnostics_debounce_ms: 150,
    diagnostics_wait_ms: 5_000,
    max_results: 200,
    max_frame_bytes: 8 * 1024 * 1024,
    # Open documents per server, and in-flight requests per server. Both are mailbox
    # bounds: past them the pool refuses rather than queues.
    max_documents: 500,
    max_pending_requests: 64,
    # Diagnostic items retained per document. Past this the cache keeps the first N and
    # counts the rest, so a server emitting thousands does not become this node's memory.
    max_diagnostics_per_document: 500,
    # The largest file the pool will read and hand to a language server. A generated
    # bundle past this is not synchronised: it is a memory problem for both processes.
    max_document_bytes: 2 * 1024 * 1024,
    # Operator-supplied server definitions, merged over the built-in registry.
    servers: [],
    # Reads a resident-set size in bytes for an OS pid. Replaced in tests; in production
    # it shells out to `ps`, which is the only portable reader available here.
    rss_reader: {Ouroboros.CodeIntel.Memory, :rss_bytes, []}
  ]

  @doc "Returns one setting, falling back to the shipped default when it is unusable."
  @spec get(atom()) :: term()
  def get(key) when is_atom(key) do
    default = Keyword.fetch!(@defaults, key)
    configured = Application.get_env(:ouroboros, :code_intel, [])

    value =
      if Keyword.keyword?(configured), do: Keyword.get(configured, key, default), else: default

    if valid?(default, value), do: value, else: default
  end

  @spec enabled?() :: boolean()
  def enabled?, do: get(:enabled) == true

  @doc "The client identity sent in `initialize`; some servers key behaviour on it."
  @spec client_info() :: map()
  def client_info do
    version =
      case :application.get_key(:ouroboros, :vsn) do
        {:ok, vsn} -> List.to_string(vsn)
        _undefined -> "0.0.0"
      end

    %{"name" => "ouroboros", "version" => version}
  end

  defp valid?(default, value) when is_integer(default) and default > 0,
    do: is_integer(value) and value > 0

  defp valid?(default, value) when is_boolean(default), do: is_boolean(value)
  defp valid?(default, value) when is_list(default), do: is_list(value)

  defp valid?({_module, _function, _args}, {module, function, args})
       when is_atom(module) and is_atom(function) and is_list(args),
       do: true

  defp valid?({_module, _function, _args}, value), do: is_function(value, 1)
  defp valid?(_default, _value), do: true
end
