defmodule Ouroboros.Web do
  @moduledoc """
  The browser operator surface: a token-authenticated, loopback-default LiveView endpoint.

  This is the gateway's argument again with a different transport in front of it. It is
  the seam a browser attaches to, it can mutate the runtime when its scope says so, and
  it is configured the way an operator console should be: off unless asked for, refusing
  to start without a credential, and on this host unless someone typed otherwise.

  ## Fail closed at init

  `init/1` builds an `Ouroboros.Web.Config` before it names a single child. A surface
  enabled without a token source, or without `OUROBOROS_DATA_DIR`, or bound off this host
  without `OUROBOROS_WEB_ALLOW_REMOTE=1`, raises here with the variable named — the
  posture `Ouroboros.Gateway` takes toward a listener with no token, and
  `Ouroboros.Upgrade.Signing.Service` takes toward a signer node with no key. An endpoint
  that starts anyway and refuses per request looks, from the outside, exactly like one
  that is deliberately refusing, and those two need very different operator responses.

  ## Shape

      Ouroboros.Web                    (rest_for_one)
      ├─ Task.Supervisor               one task per in-flight runtime call
      ├─ Ouroboros.Web.Endpoint        binds, serves HTTP and the LiveView socket
      └─ Ouroboros.Web.Publication     writes web.json, removes it on the way out

  `rest_for_one`, in that order. The task supervisor has to exist before a request can be
  served, and the publication has to name a port that is currently bound — so an endpoint
  that restarts on a different port takes the publication with it, and the file can never
  point at a socket nobody is listening on.

  ## Placement

  Started only on a `:core` node, as the final child of `Ouroboros.Application`'s
  `rest_for_one` chain, after the MCP subtree. Under that strategy its crash then
  restarts nothing, and it is the second child in the tree a stranger can reach, which is
  the same argument that put the gateway at the tail and then put everything owning no
  durable state after it. `:builder` and `:signer` nodes never run it.

  ## Honest limits

  The token authenticates a browser; loopback is the boundary that does the real work.
  v1 ships no TLS, so the documented remote posture is `tailscale serve` or an operator's
  own reverse proxy in front of the loopback bind, and the refusal for a non-loopback
  bind says exactly that. Everything this surface can do, it does through
  `Ouroboros.Web.Call` and therefore through the gateway's own method table — there is
  one authorization surface, not two.
  """

  use Supervisor

  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Endpoint
  alias Ouroboros.Web.Publication

  @doc """
  Starts the web surface.

  Options are for tests and for an operator supplying configuration another way:
  `:name`, `:config`, `:endpoint`, `:task_supervisor`, and `:server` (false starts the
  endpoint without binding a socket, which is what a conn test wants). Everything omitted
  comes from application environment, which `config/runtime.exs` writes.
  """
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(opts) do
    config = Keyword.get_lazy(opts, :config, &Config.load!/0)
    endpoint = Keyword.get(opts, :endpoint, Endpoint)
    task_supervisor = Keyword.get(opts, :task_supervisor, __MODULE__.TaskSupervisor)
    server? = Keyword.get(opts, :server, true)

    children =
      [
        {Task.Supervisor, name: task_supervisor},
        %{
          id: endpoint,
          start: {Endpoint, :start_endpoint, [endpoint, config, [server: server?]]},
          type: :supervisor
        }
      ] ++ publication_children(config, endpoint, server?)

    Supervisor.init(children, strategy: :rest_for_one)
  end

  # Nothing to publish when nothing is bound. A conn test dispatches straight into the
  # endpoint and would otherwise write a `web.json` naming a port that does not exist.
  defp publication_children(_config, _endpoint, false), do: []

  defp publication_children(config, endpoint, true) do
    [{Publication, config: config, endpoint: endpoint}]
  end
end
